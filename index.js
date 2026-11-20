import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

const app = express();
const port = process.env.PORT || 5000;

const BETTER_AUTH_URL = process.env.BETTER_AUTH_URL;

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);
app.use(
  express.json({
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    },
  })
);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI);

await client.connect();

console.log("Successfully connected to MongoDB!");

// Database collections
const db = client.db(process.env.MONGODB_DB_NAME || "equipment-rental");
const usersCollection = db.collection("user");
const equipmentCollection = db.collection("equipment");
const bookingsCollection = db.collection("bookings");
const favoritesCollection = db.collection("favorites");
const paymentsCollection = db.collection("payments");
const reviewsCollection = db.collection("reviews");

const JWKS = createRemoteJWKSet(
  new URL(`${BETTER_AUTH_URL.replace(/\/$/, "")}/api/auth/jwks`)
);

// Verify JWT and load the current user from MongoDB
const verifyToken = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized access. Token is required.",
      });
    }
    const token = authorization.split(" ")[1];
    const { payload } = await jwtVerify(token, JWKS);

    // Better Auth JWT normally includes the user's ID in "sub"
    const userId = payload.sub;
    const email = payload.email;

    if (!userId && !email) {
      return res.status(401).send({
        success: false,
        message: "Invalid token payload",
      });
    }
    let user = null;
    if (userId && ObjectId.isValid(userId)) {
      user = await usersCollection.findOne({
        _id: new ObjectId(userId),
      });
    }
    if (!user && userId) {
      user = await usersCollection.findOne({
        id: userId,
      });
    }
    if (!user && email) {
      user = await usersCollection.findOne({
        email: email.toLowerCase(),
      });
    }
    if (!user) {
      return res.status(401).send({
        success: false,
        message: "User not found.",
      });
    }
    // Attach verified user information to the request
    req.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role || "customer",
      image: user.image || "",
    };
    next();
  } catch (error) {
    console.error("JWT verification error:", error.message);
    return res.status(401).send({
      success: false,
      message: "Invalid or expired authentication token.",
    });
  }
};

// SECTION 7: ROLE-BASED AUTHORIZATION

// Customer-only access
const verifyCustomer = (req, res, next) => {
  if (req.user?.role !== "customer") {
    return res.status(403).send({
      success: false,
      message: "Customer access only.",
    });
  }
  next();
};

// Owner-only access
const verifyOwner = (req, res, next) => {
  if (req.user?.role !== "owner") {
    return res.status(403).send({
      success: false,
      message: "Owner access only.",
    });
  }
  next();
};

// OWNER DASHBOARD: EQUIPMENT HELPERS
const equipmentCategories = [
  "Construction Equipment",
  "Photography Equipment",
  "Vehicles & Transportation",
  "Agriculture Equipment",
  "Electronics",
  "Event Equipment",
];

const rentalTypes = ["daily", "weekly", "monthly"];

const equipmentConditions = ["New", "Like New", "Good", "Fair"];

const validateEquipmentData = (data) => {
  const {
    name,
    description,
    category,
    location,
    price,
    rentalType,
    availableQuantity,
    condition,
    brand,
    model,
    imageUrl,
    rentalItems,
  } = data;

  if (
    !name?.trim() ||
    !description?.trim() ||
    !category ||
    !location?.trim() ||
    !price ||
    !rentalType ||
    availableQuantity === undefined ||
    !condition ||
    !brand?.trim() ||
    !model?.trim() ||
    !imageUrl?.trim() ||
    !rentalTerms?.trim()
  ) {
    return "Please provide all required equipment information.";
  }
  if (!equipmentCategories.includes(category)) {
    return "Invalid equipment category.";
  }
  if (!rentalTypes.includes(rentalType)) {
    return "Invalid rental type.";
  }
  if (!equipmentConditions.includes(condition)) {
    return "Invalid equipment condition.";
  }
  if (!Number.isFinite(Number(price)) || Number(price) <= 0) {
    return "Rental price must be greater than zero.";
  }
  if (
    !Number.isInteger(Number(availableQuantity)) ||
    Number(availableQuantity) < 1
  ) {
    return "Available quantity must be a positive integer.";
  }
  if (!/^https:\/\//i.test(imageUrl)) {
    return "A valid HTTPS equipment image URL is required.";
  }
  return null;
};

// OWNER DASHBOARD: ADD EQUIPMENT
app.post("/api/owner/equipment", verifyToken, verifyOwner, async (req, res) => {
  try {
    const validationError = validateEquipmentData(req.body);
    if (validationError) {
      return res.status(400).send({
        success: false,
        message: validationError,
      });
    }
    const {
      name,
      description,
      category,
      location,
      price,
      rentalType,
      availableQuantity,
      condition,
      brand,
      model,
      imageUrl,
      rentalTerms,
    } = req.body;
    const now = new Date();
    const equipment = {
      name: name.trim(),
      description: description.trim(),
      category,
      location: location.trim(),
      price: Number(price),
      pricePerDay: Number(price),
      rentalType,
      availableQuantity: Number(availableQuantity),
      condition,
      brand: brand.trim(),
      model: model.trim(),
      imageUrl: imageUrl.trim(),
      images: [imageUrl.trim()],
      rentalTerms: rentalTerms.trim(),
      ownerId: req.user.id,
      ownerName: req.user.name,
      ownerEmail: req.user.email,
      ownerImage: req.user.image || "",
      status: "pending",
      createdAt: now,
      updatedAt: now,
    };
    const result = await equipmentCollection.insertOne(equipment);
    return res.status(201).send({
      success: true,
      message: "Equipment submitted for admin approval.",
      equipment: {
        ...equipment,
        _id: result.insertedId.toString(),
      },
    });
  } catch (error) {
    console.error("Add equipment error:", error);
    return res.status(500).send({
      success: false,
      message: "Failed to add equipment.",
    });
  }
});

// OWNER DASHBOARD: MY EQUIPMENT

app.get("/api/owner/equipment", verifyToken, verifyOwner, async (req, res) => {
  try {
    const equipment = await equipmentCollection
      .find({
        ownerId: req.user.id,
      })
      .sort({
        createdAt: -1,
      })
      .toArray();

    return res.status(200).send({
      success: true,
      count: equipment.length,
      equipment,
    });
  } catch (error) {
    console.error("Get owner equipment error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to fetch your equipment.",
    });
  }
});

// Single Equipment Details
app.get(
  "/api/owner/equipment/:id",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID.",
        });
      }
      const equipment = await equipmentCollection.findOne({
        _id: new ObjectId(id),
        ownerId: req.user.id,
      });
      if (!equipment) {
        return res.status(404).send({
          success: false,
          message: "Equipment not found.",
        });
      }
      return res.status(200).send({
        success: true,
        equipment,
      });
    } catch (error) {
      console.error("Get equipment error:", error);
      return res.status(500).send({
        success: false,
        message: "Failed to fetch equipment details.",
      });
    }
  }
);

// OWNER DASHBOARD: UPDATE EQUIPMENT
app.patch(
  "/api/owner/equipment/:id",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID.",
        });
      }
      const validationError = validateEquipmentData(req.body);
      if (validationError) {
        return res.status(400).send({
          success: false,
          message: validationError,
        });
      }
      const {
        name,
        description,
        category,
        location,
        price,
        rentalType,
        availableQuantity,
        condition,
        brand,
        model,
        imageUrl,
        rentalTerms,
      } = req.body;
      const updateData = {
        name: name.trim(),
        description: description.trim(),
        category,
        location: location.trim(),
        price: Number(price),
        pricePerDay: Number(price),
        rentalType,
        availableQuantity: Number(availableQuantity),
        condition,
        brand: brand.trim(),
        model: model.trim(),
        imageUrl: imageUrl.trim(),
        images: [imageUrl.trim()],
        rentalTerms: rentalTerms.trim(),
        updatedAt: new Date(),
      };
      const result = await equipmentCollection.updateOne(
        {
          _id: new ObjectId(id),
          ownerId: req.user.id,
        },
        {
          $set: updateData,
        }
      );
      if (result.matchedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Equipment not found.",
        });
      }
      return res.status(200).send({
        success: true,
        message: "Equipment updated Successfully.",
      });
    } catch (error) {
      console.error("Update equipment error:", error);
      return res.status(500).send({
        success: false,
        message: "Failed to update equipment.",
      });
    }
  }
);

// OWNER DASHBOARD: DELETE EQUIPMENT
app.delete(
  "/api/owner/equipment/:id",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID.",
        });
      }
      const equipment = await equipmentCollection.findOne({
        _id: new ObjectId(id),
        ownerId: req.user.id,
      });
      if (!equipment) {
        return res.status(404).send({
          success: false,
          message: "Equipment not found.",
        });
      }
      const activeBooking = await bookingsCollection.findOne({
        equipmentId: id,
        status: "confirmed",
        endDate: {
          $gt: new Date(),
        },
      });
      if (activeBooking) {
        return res.status(409).send({
          success: false,
          message: "Cannot delete equipment with active rentals.",
        });
      }
      await equipmentCollection.deleteOne({
        _id: new ObjectId(id),
        ownerId: req.user.id,
      });
      return res.status(200).send({
        success: true,
        message: "Equipment deleted Successfully.",
      });
    } catch (error) {
      console.error("Delete equipment error:", error);
      return res.status(500).send({
        success: false,
        message: "Failed to delete equipment.",
      });
    }
  }
);

//OWNER DASHBOARD: MY EQUIPMENT RENTALS
app.get("/api/owner/rentals", verifyToken, verifyOwner, async (req, res) => {
  try {
    const rentals = await bookingsCollection
      .aggregate([
        {
          $match: {
            ownerId: req.user.id,
          },
        },
        {
          $addFields: {
            equipmentObjectId: {
              $convert: {
                input: "$equipmentId",
                to: "ObjectId",
                onError: null,
                onNull: null,
              },
            },
          },
        },
        {
          $lookup: {
            from: "equipment",
            localField: "equipmentObjectId",
            foreignField: "_id",
            as: "equipment",
          },
        },
        {
          $unwind: {
            path: "$equipment",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $sort: {
            createdAt: -1,
          },
        },
        {
          $project: {
            customerId: 1,
            customerName: 1,
            customerEmail: 1,
            contactNumber: 1,
            deliveryAddress: 1,

            equipmentId: 1,
            equipmentName: 1,
            equipmentImage: 1,

            startDate: 1,
            endDate: 1,
            rentalDays: 1,
            rentalType: 1,
            quantity: 1,

            totalAmount: 1,
            currency: 1,

            paymentStatus: 1,
            status: 1,

            createdAt: 1,
            equipment: {
              name: "$equipment.name",
              category: "$equipment.category",
              imageUrl: "$equipment.imageUrl",
            },
          },
        },
      ])
      .toArray();

    return res.status(200).send({
      success: true,
      count: rentals.length,
      rentals,
    });
  } catch (error) {
    console.error("Owner rentals error:", error);
    return res.status(500).send({
      success: false,
      message: "Failed to fetch equipment rentals.",
    });
  }
});

// Admin-only access
const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).send({
      success: false,
      message: "Admin access only.",
    });
  }
  next();
};

// owner or Admin access
const verifyOwnerOrAdmin = (req, res, next) => {
  if (!["owner", "admin"].includes(req.user?.role)) {
    return res.status(403).send({
      success: false,
      message: "Owner or Admin access only",
    });
  }
  next();
};

// FEATURED EQUIPMENT API
// Get latest 6 approved equipment items
app.get("/api/equipment/featured", async (req, res) => {
  try {
    const equipment = await equipmentCollection
      .find({ status: "approved" })
      .sort({ createdAt: -1 })
      .limit(6)
      .toArray();

    res.status(200).send({
      success: true,
      count: equipment.length,
      equipment,
    });
  } catch (error) {
    console.error("Featured equipment error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch featured equipment",
    });
  }
});

// Get API Status
app.get("/", (req, res) => {
  res.send({
    success: true,
    message: "Equipora API is running",
  });
});

// Start Server
app.listen(port, () => {
  console.log(`Equipora API running on port ${port}`);
});

export default app;
