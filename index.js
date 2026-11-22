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
    origin: [
      "http://localhost:3000",
      "https://equipment-rental-client-ecru.vercel.app",
    ],
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

// Customer helper
const getCustomerIdentityFilter = (user) => {
  const conditions = [];

  if (user?.id) {
    conditions.push({ customerId: user.id }, { userId: user.id });
  }
  if (user?.email) {
    conditions.push({
      customerEmail: user.email.toLowerCase(),
    });

    conditions.push({
      userEmail: user.email.toLowerCase(),
    });
  }
  return conditions.length ? { $or: conditions } : null;
};

const getFavoriteIdentityFilter = (user) => {
  const conditions = [];
  if (user?.id) {
    conditions.push({ userId: user.id }, { customerId: user.id });
  }
  if (user?.email) {
    conditions.push({
      userEmail: user.email.toLowerCase(),
    });

    conditions.push({
      customerEmail: user.email.toLowerCase(),
    });
  }
  return conditions.length ? { $or: conditions } : null;
};

const getProfileIdentityFilter = (user) => {
  const conditions = [];

  if (user?.id) {
    conditions.push(
      { id: user.id },
      ...(ObjectId.isValid(user.id) ? [{ _id: new ObjectId(user.id) }] : [])
    );
  }
  if (user?.email) {
    conditions.push({
      email: user.email.toLowerCase(),
    });
  }

  return conditions.length ? { $or: conditions } : null;
};

// My Rentals — GET
app.get(
  "/api/customer/my-rentals",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const identityFilter = getCustomerIdentityFilter(req.user);
      if (!identityFilter) {
        return res.status(401).send({
          success: false,
          message: "Unable to identify customer",
        });
      }
      const rentals = await bookingsCollection
        .find(identityFilter)
        .sort({ createdAt: -1 })
        .toArray();
      res.status(200).send({
        success: true,
        count: rentals.length,
        rentals: rentals.map((rental) => ({
          ...rental,
          _id: rental._id.toString(),
        })),
      });
    } catch (error) {
      console.error("Customer rentals error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to fetch your rentals",
      });
    }
  }
);

// Favorites — GET
app.get(
  "/api/customer/favorites",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const identityFilter = getFavoriteIdentityFilter(req.user);
      if (!identityFilter) {
        return res.status(401).send({
          success: false,
          message: "Unable to identify customer",
        });
      }
      const favorites = await favoritesCollection
        .find(identityFilter)
        .sort({ createdAt: -1 })
        .toArray();

      if (!favorites.length) {
        return res.status(200).send({
          success: true,
          count: 0,
          favorites: [],
        });
      }

      const equipmentIds = favorites
        .map((favorite) => favorite.equipmentId)
        .filter(Boolean);

      const objectIds = equipmentIds
        .filter((id) => ObjectId.isValid(String(id)))
        .map((id) => new ObjectId(String(id)));

      const stringIds = equipmentIds.map((id) => String(id));

      // const equipment = equipmentCollection
      //   .find({
      //     $or: [{ _id: { $in: objectIds } }, { id: { $in: stringIds } }],
      //   })
      //   .toArray();

      // Fetch equipment documents
      const equipmentDocs = await equipmentCollection
        .find({
          $or: [{ _id: { $in: objectIds } }, { id: { $in: stringIds } }],
        })
        .toArray();

      // Validate MongoDB result
      if (!Array.isArray(equipmentDocs)) {
        console.error("Expected equipment array, received:", equipmentDocs);

        throw new Error("Equipment query did not return an array");
      }

      const equipmentMap = new Map();

      equipmentDocs.forEach((item) => {
        equipmentMap.set(item._id.toString(), item);

        if (item.id) {
          equipmentMap.set(String(item.id), item);
        }
      });

      const result = favorites
        .map((favorite) => {
          const item = equipmentMap.get(String(favorite.equipmentId));
          if (!item) return null;
          return {
            _id: favorite._id.toString(),
            favoriteId: favorite._id.toString(),
            createdAt: favorite.createdAt,
            equipment: {
              ...item,
              _id: item._id.toString(),
            },
          };
        })
        .filter(Boolean);

      res.status(200).send({
        success: true,
        count: result.length,
        favorites: result,
      });
    } catch (error) {
      console.error("Customer favorites error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to fetch favorites",
      });
    }
  }
);

// Remove Favorite — DELETE
app.delete(
  "/api/customer/favorites/:id",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid favorite ID",
        });
      }
      const identityFilter = getFavoriteIdentityFilter(req.user);
      if (!identityFilter) {
        return res.status(401).send({
          success: false,
          message: "Unable to identify customer",
        });
      }
      const result = await favoritesCollection.deleteOne({
        $and: [{ _id: new ObjectId(id) }, identityFilter],
      });
      if (!result.deletedCount) {
        return res.status(404).send({
          success: false,
          message: "Favorite not found",
        });
      }
      res.status(200).send({
        success: true,
        message: "Favorite removed successfully",
      });
    } catch (error) {
      console.error("Remove favorite error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to remove favorite",
      });
    }
  }
);
// Shared Profile — GET
app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const identityFilter = getProfileIdentityFilter(req.user);
    if (!identityFilter) {
      return res.status(401).send({
        success: false,
        message: "Unable to identify user",
      });
    }
    const profile = await usersCollection.findOne(identityFilter, {
      projection: {
        name: 1,
        email: 1,
        role: 1,
        image: 1,
        phone: 1,
        address: 1,
        createdAt: 1,
        updatedAt: 1,
      },
    });
    if (!profile) {
      return res.status(404).send({
        success: false,
        message: "Profile not found",
      });
    }

    res.status(200).send({
      success: true,
      profile: {
        ...profile,
        _id: profile._id?.toString() || profile.id,
        role: profile.role || "customer",
      },
    });
  } catch (error) {
    console.error("Get profile error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch profile",
    });
  }
});

// Shared Profile — PATCH
app.patch("/api/profile", verifyToken, async (req, res) => {
  try {
    const { name, phone, address, image } = req.body;
    const updates = {};
    if (name !== undefined) {
      if (
        typeof name !== "string" ||
        name.trim().length < 2 ||
        name.trim().length > 80
      ) {
        return res.status(400).send({
          success: false,
          message: "Name must be between 2 and 80 characters",
        });
      }
      updates.name = name.trim();
    }
    if (phone !== undefined) {
      if (typeof phone !== "string" || phone.length > 25) {
        return res.status(400).send({
          success: false,
          message: "Invalid phone number",
        });
      }

      updates.phone = phone.trim();
    }
    if (address !== undefined) {
      if (typeof address !== "string" || address.length > 300) {
        return res.status(400).send({
          success: false,
          message: "Address must be under 300 characters",
        });
      }

      updates.address = address.trim();
    }
    if (image !== undefined) {
      if (typeof image !== "string" || image.length > 2000) {
        return res.status(400).send({
          success: false,
          message: "Invalid profile image URL",
        });
      }

      if (image.trim()) {
        try {
          const parsedUrl = new URL(image.trim());

          if (!["http:", "https:"].includes(parsedUrl.protocol)) {
            throw new Error("Invalid protocol");
          }
        } catch {
          return res.status(400).send({
            success: false,
            message: "Please provide a valid image URL",
          });
        }
      }

      updates.image = image.trim();
    }
    if (!Object.keys(updates).length) {
      return res.status(400).send({
        success: false,
        message: "No valid profile fields provided",
      });
    }
    const identityFilter = getProfileIdentityFilter(req.user);
    if (!identityFilter) {
      return res.status(401).send({
        success: false,
        message: "Unable to identify user",
      });
    }
    updates.updatedAt = new Date();
    const result = await usersCollection.updateOne(identityFilter, {
      $set: updates,
    });
    if (!result.matchedCount) {
      return res.status(404).send({
        success: false,
        message: "Profile not found",
      });
    }
    res.status(200).send({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Update profile error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to update profile",
    });
  }
});

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
    rentalTerms,
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

// Admin helper functions
const getAdminUserId = (user) => {
  return user?.id || user?._id?.toString() || "";
};

const getAdminUserFilter = (user) => {
  const conditions = [];
  if (user?.id) {
    conditions.push({ _id: user.id }, { id: user.id });
  }
  if (user?.email) {
    conditions.push({ email: user.email.toLowerCase() });
  }
  return conditions.length ? { $or: conditions } : null;
};
const getEquipmentOwnerFilter = (equipment) => ({
  $or: [{ ownerId: equipment.ownerId }, { ownerEmail: equipment.ownerEmail }],
});

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
                to: "objectId",
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
    // console.error("Owner rentals error:", error);

    // return res.status(500).send({
    //   success: false,
    //   message: "Failed to fetch equipment rentals.",
    // });
    console.error("Owner rentals error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch equipment rentals.",
      error: error.message, // Development debugging
    });
  }
});

// OWNER DASHBOARD: PROFILE
// GET OWNER PROFILE

app.get("/api/owner/profile", verifyToken, verifyOwner, async (req, res) => {
  try {
    const owner = await usersCollection.findOne(
      {
        _id: new ObjectId(req.user.id),
      },
      {
        projection: {
          password: 0,
        },
      }
    );
    if (!owner) {
      return res.status(404).send({
        success: false,
        message: "Owner profile not found.",
      });
    }
    return res.status(200).send({
      success: true,
      profile: {
        id: owner._id.toString(),
        name: owner.name || "",
        email: owner.email || "",
        image: owner.image || "",
        phone: owner.phone || "",
        role: owner.role,
      },
    });
  } catch (error) {
    console.error("Owner profile error:", error);
    return res.status(500).send({
      success: false,
      message: "Failed to fetch owner profile.",
    });
  }
});

// UPDATE OWNER PROFILE
app.patch("/api/owner/profile", verifyToken, verifyOwner, async (req, res) => {
  try {
    const { name, phone, image } = req.body;

    if (!name?.trim() || name.trim().length < 2) {
      return res.status(400).send({
        success: false,
        message: "Name must contain at least 2 characters.",
      });
    }

    if (phone && !/^[+0-9()\-\s]{7,20}$/.test(phone)) {
      return res.status(400).send({
        success: false,
        message: "Invalid phone number.",
      });
    }
    if (image && !/^https:\/\//i.test(image)) {
      return res.status(400).send({
        success: false,
        message: "Invalid profile image URL.",
      });
    }
    const result = await usersCollection.updateOne(
      {
        _id: new ObjectId(req.user.id),
        role: "owner",
      },
      {
        $set: {
          name: name.trim(),
          phone: phone?.trim() || "",
          ...(image !== undefined ? { image } : {}),
          updatedAt: new Date(),
        },
      }
    );
    if (!result.matchedCount) {
      return res.status(404).send({
        success: false,
        message: "Owner profile not found.",
      });
    }
    return res.status(200).send({
      success: true,
      message: "Profile updated successfully.",
    });
  } catch (error) {
    console.error("Update owner profile error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to update owner profile.",
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

// All Users — GET/Admin
app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection
      .find({})
      .project({
        name: 1,
        email: 1,
        role: 1,
        image: 1,
        createdAt: 1,
        updatedAt: 1,
      })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).send({
      success: true,
      count: users.length,
      users: users.map((user) => ({
        ...user,
        _id: user._id?.toString() || user.id,
        role: user.role || "customer",
      })),
    });
  } catch (error) {
    console.error("Admin users error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch users",
    });
  }
});

// Change User Role — PATCH
app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;
      const allowedRoles = ["customer", "owner", "admin"];
      if (!allowedRoles.includes(role)) {
        return res.status(400).send({
          success: false,
          message: "Invalid user role",
        });
      }
      const targetUser = await usersCollection.findOne({
        $or: [{ _id: ObjectId.isValid(id) ? new ObjectId(id) : null }, { id }],
      });
      if (!targetUser) {
        return res.status(404).send({
          success: false,
          message: "User not found",
        });
      }
      const currentAdmin = await usersCollection.findOne(
        getAdminUserFilter(req.user) || { email: "__not_found__" }
      );
      const targetId = targetUser._id?.toString() || targetUser.id;

      const adminId = currentAdmin?._id?.toString() || currentAdmin?.id;

      if (targetId === adminId) {
        return res.status(403).send({
          success: false,
          message: "You cannot change your own admin role",
        });
      }
      await usersCollection.updateOne(
        { _id: targetUser._id },
        {
          $set: {
            role,
            updatedAt: new Date(),
          },
        }
      );
      res.status(200).send({
        success: true,
        message: "User role updated successfully",
      });
    } catch (error) {
      console.error("Change role error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to update user role",
      });
    }
  }
);
// Manage Users — DELETE
app.delete(
  "/api/admin/users/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const targetUser = await usersCollection.findOne({
        $or: [{ _id: ObjectId.isValid(id) ? new ObjectId(id) : null }, { id }],
      });
      if (!targetUser) {
        return res.status(404).send({
          success: false,
          message: "User not found",
        });
      }
      const currentAdmin = await usersCollection.findOne(
        getAdminUserFilter(req.user) || { email: "__not_found__" }
      );
      const targetId = targetUser._id?.toString() || targetUser.id;
      const adminId = currentAdmin?._id?.toString() || currentAdmin?.id;

      if (targetId === adminId) {
        return res.status(403).send({
          success: false,
          message: "You cannot delete your own account",
        });
      }
      await usersCollection.deleteOne({ _id: targetUser._id });
      res.status(200).send({
        success: true,
        message: "User deleted successfully",
      });
    } catch (error) {
      console.error("Delete user error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to delete user",
      });
    }
  }
);

// All Equipment — GET
app.get("/api/admin/equipment", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const equipment = await equipmentCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).send({
      success: true,
      count: equipment.length,
      equipment,
    });
  } catch (error) {
    console.error("Admin equipment error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch equipment",
    });
  }
});
// Approve / Reject Equipment — PATCH
app.patch(
  "/api/admin/equipment/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
      const allowedStatuses = ["pending", "approved", "rejected"];
      if (!allowedStatuses.includes(status)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment status",
        });
      }
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID.",
        });
      }
      const result = await equipmentCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        }
      );
      if (!result.matchedCount) {
        return res.status(404).send({
          success: false,
          message: "Equipment not found",
        });
      }
      res.status(200).send({
        success: true,
        message: `Equipment ${status} successfully`,
      });
    } catch (error) {
      console.error("Equipment status error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to update equipment status",
      });
    }
  }
);

// Update Equipment — PATCH
app.patch(
  "/api/admin/equipment/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID.",
        });
      }
      const allowedFields = [
        "name",
        "description",
        "category",
        "location",
        "price",
        "rentalType",
        "availableQuantity",
        "condition",
        "brand",
        "model",
        "imageUrl",
        "rentalTerms",
      ];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }
      if (!Object.keys(updates).length) {
        return res.status(400).send({
          success: false,
          message: "No valid fields provided",
        });
      }
      if (
        updates.price !== undefined &&
        (!Number.isFinite(Number(updates.price)) || Number(updates.price) <= 0)
      ) {
        return res.status(400).send({
          success: false,
          message: "Price must be greater than zero",
        });
      }
      if (updates.price !== undefined) {
        updates.price = Number(updates.price);
      }
      if (updates.availableQuantity !== undefined) {
        updates.availableQuantity = Number(updates.availableQuantity);

        if (
          !Number.isInteger(updates.availableQuantity) ||
          updates.availableQuantity < 1
        ) {
          return res.status(400).send({
            success: false,
            message: "Quantity must be at least 1",
          });
        }
      }
      updates.updatedAt = new Date();
      const result = await equipmentCollection.updateOne(
        {
          _id: new ObjectId(id),
        },
        { $set: updates }
      );
      if (!result.matchedCount) {
        return res.status(404).send({
          success: false,
          message: "Equipment not found",
        });
      }
      res.status(200).send({
        success: true,
        message: "Equipment updated successfully",
      });
    } catch (error) {
      console.error("Admin equipment update error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to update equipment",
      });
    }
  }
);

// Delete Equipment — DELETE
app.delete(
  "/api/admin/equipment/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID",
        });
      }
      const result = await equipmentCollection.deleteOne({
        _id: new ObjectId(id),
      });
      if (!result.deletedCount) {
        return res.status(404).send({
          success: false,
          message: "Equipment not found",
        });
      }
      res.status(200).send({
        success: true,
        message: "Equipment deleted successfully",
      });
    } catch (error) {
      console.error("Admin equipment delete error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to delete equipment",
      });
    }
  }
);

// Amdin Rentals - GET
app.get("/api/admin/rentals", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const rentals = await bookingsCollection
      .aggregate([
        {
          $lookup: {
            from: "equipment",
            let: { equipmentId: "$equipmentId" },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $eq: [
                      { $toString: "$_id" },
                      { $toString: "$$equipmentId" },
                    ],
                  },
                },
              },
            ],
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
          $sort: { createdAt: -1 },
        },
      ])
      .toArray();

    res.status(200).json({
      success: true,
      message: "All rentals retrieved successfully",
      rentals,
    });
  } catch (error) {
    console.error("Admin rentals error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve rentals",
    });
  }
});

// Manage Rental Status — PATCH
app.patch(
  "/api/admin/rentals/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      const allowedStatuses = [
        "pending",
        "confirmed",
        "active",
        "completed",
        "cancelled",
        "rejected",
      ];
      if (!allowedStatuses.includes(status)) {
        return res.status(400).send({
          success: false,
          message: "Invalid rental status",
        });
      }
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid rental ID",
        });
      }
      const result = await bookingsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        }
      );
      if (!result.matchedCount) {
        return res.status(404).send({
          success: false,
          message: "Rental not found",
        });
      }
      res.status(200).send({
        success: true,
        message: "Rental status updated successfully",
      });
    } catch (error) {
      console.error("Rental status error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to update rental status",
      });
    }
  }
);

// Admin Profile — GET / PATCH
app.get("/api/admin/profile", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const user = await usersCollection.findOne(
      getAdminUserFilter(req.user) || { email: "__not_found__" },
      {
        projection: {
          name: 1,
          email: 1,
          role: 1,
          image: 1,
          phone: 1,
          createdAt: 1,
        },
      }
    );
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Admin profile not found",
      });
    }
    res.status(200).send({
      success: true,
      profile: {
        ...user,
        _id: user._id?.toString() || user.id,
      },
    });
  } catch (error) {
    console.error("Admin profile error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch profile",
    });
  }
});

app.patch("/api/admin/profile", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { name, phone, image } = req.body;
    const updates = {};
    if (name !== undefined) {
      if (typeof name !== "string" || name.trim().length < 2) {
        return res.status(400).send({
          success: false,
          message: "Name must contain at least 2 characters",
        });
      }
      updates.name = name.trim();
    }
    if (phone !== undefined) {
      updates.phone = String(phone).trim();
    }

    if (image !== undefined) {
      updates.image = String(image).trim();
    }
    if (!Object.keys(updates).length) {
      return res.status(400).send({
        success: false,
        message: "No profile fields provided",
      });
    }
    updates.updatedAt = new Date();

    const filter = getAdminUserFilter(req.user);
    if (!filter) {
      return res.status(401).send({
        success: false,
        message: "Unable to identify admin",
      });
    }
    const result = await usersCollection.updateOne(filter, { $set: updates });
    if (!result.matchedCount) {
      return res.status(404).send({
        success: false,
        message: "Admin profile not found",
      });
    }
    res.status(200).send({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Admin profile update error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to update profile",
    });
  }
});
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

// All Approved Equipment

app.get("/api/equipment", async (req, res) => {
  try {
    const {
      search = "",
      category = "",
      rentalType = "",
      minPrice = "",
      maxPrice = "",
      availability = "",
      sort = "recent",
      page = "1",
      limit = "12",
    } = req.query;

    // 1. Pagination validation
    const currentPage = Math.max(1, Number(page) || 1);

    const pageLimit = Math.min(50, Math.max(1, Number(limit) || 12));

    // 2. Safely escape search regex
    const escapeRegex = (value) =>
      String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    // 3. Base MongoDB filter
    const match = {
      status: "approved",
    };

    // 4. Search by title, name, category and location
    if (search && String(search).trim()) {
      const searchRegex = new RegExp(escapeRegex(String(search).trim()), "i");

      match.$or = [
        { title: searchRegex },
        { name: searchRegex },
        { category: searchRegex },
        { location: searchRegex },
      ];
    }

    // 5. Category filter
    if (category) {
      match.category = String(category);
    }

    // 6. Rental type filter
    if (rentalType) {
      match.rentalType = String(rentalType);
    }

    // 7. Price validation
    const min = minPrice === "" ? null : Number(minPrice);

    const max = maxPrice === "" ? null : Number(maxPrice);

    if (
      (min !== null && (!Number.isFinite(min) || min < 0)) ||
      (max !== null && (!Number.isFinite(max) || max < 0)) ||
      (min !== null && max !== null && min > max)
    ) {
      return res.status(400).send({
        success: false,
        message: "Invalid price range.",
      });
    }

    // 8. Aggregation pipeline
    const pipeline = [
      {
        $match: match,
      },
      {
        $addFields: {
          displayPrice: {
            $convert: {
              input: {
                $ifNull: ["$pricePerDay", "$price"],
              },
              to: "double",
              onError: 0,
              onNull: 0,
            },
          },

          isAvailable: {
            $gt: [
              {
                $ifNull: ["$availableQuantity", 0],
              },
              0,
            ],
          },
        },
      },
    ];

    // 9. Price filter
    if (min !== null || max !== null) {
      const priceCondition = {};

      if (min !== null) {
        priceCondition.$gte = min;
      }

      if (max !== null) {
        priceCondition.$lte = max;
      }

      pipeline.push({
        $match: {
          displayPrice: priceCondition,
        },
      });
    }

    // 10. Availability filter
    if (availability === "available") {
      pipeline.push({
        $match: {
          isAvailable: true,
        },
      });
    } else if (availability === "unavailable") {
      pipeline.push({
        $match: {
          isAvailable: false,
        },
      });
    } else if (availability !== "") {
      return res.status(400).send({
        success: false,
        message: "Invalid availability filter.",
      });
    }

    // 11. Sorting
    let sortOption = {
      createdAt: -1,
    };

    if (sort === "price-low") {
      sortOption = {
        displayPrice: 1,
        createdAt: -1,
      };
    } else if (sort === "price-high") {
      sortOption = {
        displayPrice: -1,
        createdAt: -1,
      };
    } else if (sort === "recent") {
      sortOption = {
        createdAt: -1,
      };
    } else {
      return res.status(400).send({
        success: false,
        message: "Invalid sorting option.",
      });
    }

    // 12. Sort and paginate
    pipeline.push(
      {
        $sort: sortOption,
      },
      {
        $facet: {
          equipments: [
            {
              $skip: (currentPage - 1) * pageLimit,
            },
            {
              $limit: pageLimit,
            },
            {
              $project: {
                displayPrice: 1,
                isAvailable: 1,
                name: 1,
                description: 1,
                category: 1,
                location: 1,
                price: 1,
                pricePerDay: 1,
                rentalType: 1,
                availableQuantity: 1,
                condition: 1,
                brand: 1,
                model: 1,
                imageUrl: 1,
                images: 1,
                ownerId: 1,
                ownerName: 1,
                status: 1,
                createdAt: 1,
              },
            },
          ],

          totalCount: [
            {
              $count: "total",
            },
          ],
        },
      }
    );

    // 13. Execute aggregation
    const [result] = await equipmentCollection.aggregate(pipeline).toArray();

    // 14. Correctly extract equipment array
    const equipments = result?.equipments || [];

    // 15. Correctly extract total count
    const total = result?.totalCount?.[0]?.total || 0;

    // 16. Retrieve approved equipment categories
    const categories = await equipmentCollection.distinct("category", {
      status: "approved",
    });

    // 17. Send response
    return res.status(200).send({
      success: true,
      message: "Approved equipment retrieved successfully.",

      equipments,

      categories: categories.filter(Boolean).sort(),

      pagination: {
        currentPage,
        limit: pageLimit,
        total,
        totalPages: Math.ceil(total / pageLimit),
      },
    });
  } catch (error) {
    console.error("Get all equipment error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to retrieve equipment",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
});

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

// EQUIPMENT DETAILS — GET
app.get("/api/equipment/:id", verifyToken, async (req, res) => {
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
    });
    if (!equipment) {
      return res.status(404).send({
        success: false,
        message: "Equipment not found.",
      });
    }
    // Customers can only view approved equipment.
    // Owners can view their own equipment.
    // Admins can view all equipment.
    const canView =
      equipment.status === "approved" ||
      (req.user.role === "owner" && equipment.ownerId === req.user.id) ||
      req.user.role === "admin";
    if (!canView) {
      return res.status(403).send({
        success: false,
        message: "You cannot view this equipment.",
      });
    }
    return res.status(200).send({
      success: true,
      equipment: {
        ...equipment,
        _id: equipment._id.toString(),
      },
    });
  } catch (error) {
    console.error("Equipment details error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to fetch equipment details.",
    });
  }
});

// GET FAVORITES - GET

app.get(
  "/api/customer/favorites",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const identityFilter = getFavoriteIdentityFilter(req.user);

      if (!identityFilter) {
        return res.status(401).send({
          success: false,
          message: "Unable to identify customer.",
        });
      }

      // 1. Get customer favorites
      const favorites = await favoritesCollection
        .find(identityFilter)
        .sort({ createdAt: -1 })
        .toArray();

      if (!favorites.length) {
        return res.status(200).send({
          success: true,
          count: 0,
          favorites: [],
        });
      }

      // 2. Extract equipment IDs
      const equipmentIds = favorites
        .map((favorite) => String(favorite.equipmentId))
        .filter(Boolean);

      const objectIds = equipmentIds
        .filter((id) => ObjectId.isValid(id))
        .map((id) => new ObjectId(id));

      // 3. Fetch equipment documents
      const equipmentDocs = await equipmentCollection
        .find({
          $or: [{ _id: { $in: objectIds } }, { id: { $in: equipmentIds } }],
        })
        .toArray();

      // 4. Create equipment lookup map
      const equipmentMap = new Map();

      equipmentDocs.forEach((item) => {
        equipmentMap.set(item._id.toString(), item);

        if (item.id) {
          equipmentMap.set(String(item.id), item);
        }
      });

      // 5. Combine favorites with equipment
      const result = favorites
        .map((favorite) => {
          const item = equipmentMap.get(String(favorite.equipmentId));

          if (!item || item.status !== "approved") {
            return null;
          }

          return {
            favoriteId: favorite._id.toString(),
            equipmentId: item._id.toString(),
            createdAt: favorite.createdAt,
            equipment: {
              ...item,
              _id: item._id.toString(),
            },
          };
        })
        .filter(Boolean);

      // 6. Send response
      return res.status(200).send({
        success: true,
        count: result.length,
        favorites: result,
      });
    } catch (error) {
      console.error("Customer favorites error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to fetch favorites.",
      });
    }
  }
);

// ADD TO FAVORITES - POST
app.post(
  "/api/customer/favorites",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { equipmentId } = req.body;
      if (!equipmentId || !ObjectId.isValid(equipmentId)) {
        return res.status(400).send({
          success: false,
          message: "valid equipment ID is required.",
        });
      }
      const equipment = await equipmentCollection.findOne({
        _id: new ObjectId(equipmentId),
        status: "approved",
      });
      if (!equipment) {
        return res.status(404).send({
          success: false,
          message: "Approve equipment not found.",
        });
      }
      const identityFilter = getFavoriteIdentityFilter(req.user);
      if (!identityFilter) {
        return res.status(401).send({
          success: false,
          message: "Unable to identify customer",
        });
      }
      const existingFavorite = await favoritesCollection.findOne({
        $and: [identityFilter, { equipmentId: equipment._id.toString() }],
      });
      if (existingFavorite) {
        return res.status(200).send({
          success: true,
          message: "Equipment is already in your favorites.",
          favoriteId: existingFavorite._id.toString(),
        });
      }
      const favorite = {
        userId: req.user.id,
        customerId: req.user.id,
        userEmail: req.user.email.toLowerCase(),
        customerEmail: req.user.email.toLowerCase(),
        equipmentId: equipment._id.toString(),
        createdAt: new Date(),
      };
      const result = await favoritesCollection.insertOne(favorite);

      return res.status(201).send({
        success: true,
        message: "Equipment added to favorites",
        favoriteId: result.insertedId.toString(),
      });
    } catch (error) {
      console.error("Add favorite error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to add equipment to favorites.",
      });
    }
  }
);

// DELETE FAVORITES -DELETE

app.delete(
  "/api/customer/favorites/:id",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid favorite ID.",
        });
      }

      const identityFilter = getFavoriteIdentityFilter(req.user);

      if (!identityFilter) {
        return res.status(401).send({
          success: false,
          message: "Unable to identify customer.",
        });
      }

      const result = await favoritesCollection.deleteOne({
        $and: [identityFilter, { _id: new ObjectId(id) }],
      });

      if (result.deletedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Favorite not found.",
        });
      }

      return res.status(200).send({
        success: true,
        message: "Favorite removed successfully.",
      });
    } catch (error) {
      console.error("Remove favorite error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to remove favorite.",
      });
    }
  }
);

// BOOKING HELPERS
// Calculates rental units from the equipment rental type.
const calculateRentalUnits = (startDate, endDate, rentalType) => {
  const millisecondsPerDay = 24 * 60 * 60 * 1000;

  // Both selected dates are inclusive
  const rentalDays =
    Math.floor((endDate.getTime() - startDate.getTime()) / millisecondsPerDay) +
    1;
  let rentalUnits;
  if (rentalType === "daily") {
    rentalUnits = rentalDays;
  } else if (rentalType === "weekly") {
    rentalUnits = Math.ceil(rentalDays / 7);
  } else if (rentalType === "monthly") {
    rentalUnits = Math.ceil(rentalDays / 30);
  } else {
    throw new Error("Unsupported rental type.");
  }
  return { rentalDays, rentalUnits };
};

// Find quantities reserved by overlapping bookings.

const getReservedQuantity = async (equipmentId, startDate, endDate) => {
  const now = new Date();
  const overlappingBookings = await bookingsCollection
    .find({
      equipmentId,
      startDate: { $lt: endDate },
      endDate: { $gte: startDate },
      $or: [
        {
          paymentStatus: "paid",
          status: { $nin: ["cancelled", "rejected"] },
        },
        {
          paymentStatus: "pending",
          status: "pending",
          checkoutExpiresAt: { $gt: now },
        },
      ],
    })
    .project({ quantity: 1 })
    .toArray();

  return overlappingBookings.reduce(
    (total, booking) => total + Number(booking.quantity || 0),
    0
  );
};

// CREATE STRIPE CHECKOUT — POST

app.post(
  "/api/bookings/checkout",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    let bookingId;

    try {
      const {
        equipmentId,
        startDate,
        endDate,
        quantity,
        contactNumber,
        deliveryAddress,
        additionalNotes = "",
      } = req.body;

      // 1. Validate equipment ID
      if (!ObjectId.isValid(equipmentId)) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment ID.",
        });
      }

      // 2. Validate required booking information
      if (
        !startDate ||
        !endDate ||
        !Number.isInteger(Number(quantity)) ||
        Number(quantity) < 1 ||
        typeof contactNumber !== "string" ||
        !contactNumber.trim() ||
        typeof deliveryAddress !== "string" ||
        !deliveryAddress.trim()
      ) {
        return res.status(400).send({
          success: false,
          message: "Please provide all required booking information.",
        });
      }

      if (
        typeof additionalNotes !== "string" ||
        additionalNotes.length > 1000
      ) {
        return res.status(400).send({
          success: false,
          message: "Additional notes must be under 1000 characters.",
        });
      }

      // 3. Find approved equipment
      const equipment = await equipmentCollection.findOne({
        _id: new ObjectId(equipmentId),
        status: "approved",
      });

      if (!equipment) {
        return res.status(404).send({
          success: false,
          message: "Approved equipment not found.",
        });
      }

      // 4. Validate rental dates
      const start = new Date(`${startDate}T00:00:00.000Z`);
      const end = new Date(`${endDate}T00:00:00.000Z`);

      const today = new Date();
      today.setUTCHours(0, 0, 0, 0);

      if (
        Number.isNaN(start.getTime()) ||
        Number.isNaN(end.getTime()) ||
        start < today ||
        end < start
      ) {
        return res.status(400).send({
          success: false,
          message: "Please select valid rental dates.",
        });
      }

      const requestedQuantity = Number(quantity);

      // 5. Check equipment availability
      const reservedQuantity = await getReservedQuantity(
        equipment._id.toString(),
        start,
        end
      );

      const availableQuantity =
        Number(equipment.availableQuantity) - reservedQuantity;

      if (requestedQuantity > availableQuantity) {
        return res.status(409).send({
          success: false,
          message: `Only ${Math.max(
            availableQuantity,
            0
          )} item(s) are available for these dates.`,
        });
      }

      // 6. Calculate rental duration
      const { rentalDays, rentalUnits } = calculateRentalUnits(
        start,
        end,
        equipment.rentalType
      );

      // 7. Validate equipment price (USD)
      const rawUnitPrice = Number(equipment.price);

      if (!Number.isFinite(rawUnitPrice) || rawUnitPrice <= 0) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment rental price.",
        });
      }

      // Equipment price is in USD.
      // Example: $100 = 10000 cents.
      const stripeUnitAmount = Math.round(rawUnitPrice * 100);

      if (!Number.isSafeInteger(stripeUnitAmount) || stripeUnitAmount <= 0) {
        return res.status(400).send({
          success: false,
          message: "Invalid equipment rental price.",
        });
      }

      // Normalize unit price to the exact cent amount charged by Stripe.
      const unitPrice = stripeUnitAmount / 100;

      // 8. Calculate total amount in cents
      const stripeQuantity = rentalUnits * requestedQuantity;

      const stripeTotalAmount = stripeUnitAmount * stripeQuantity;

      if (!Number.isSafeInteger(stripeTotalAmount) || stripeTotalAmount <= 0) {
        return res.status(400).send({
          success: false,
          message: "Invalid Stripe payment amount.",
        });
      }

      // Stripe USD minimum amount is $0.50.
      if (stripeTotalAmount < 50) {
        return res.status(400).send({
          success: false,
          message:
            "Minimum payment amount is $0.50 USD. Please select equipment with a higher rental price or a longer rental period.",
        });
      }

      // USD is the actual equipment pricing currency.
      const currency = "usd";

      // Store amount in dollars in the booking.
      const totalAmount = stripeTotalAmount / 100;

      console.log("Stripe Amount Debug:", {
        equipmentPrice: equipment.price,
        unitPrice,
        rentalDays,
        rentalUnits,
        requestedQuantity,
        stripeQuantity,
        totalAmount,
        currency,
        stripeUnitAmount,
        stripeTotalAmount,
      });

      // 9. Validate frontend URL before creating booking
      const frontendUrl = process.env.CLIENT_URL?.replace(/\/$/, "");

      if (!frontendUrl) {
        return res.status(500).send({
          success: false,
          message: "CLIENT_URL is not configured.",
        });
      }

      // 10. Create pending booking
      const now = new Date();

      const expiresAt = new Date(now.getTime() + 30 * 60 * 1000);

      const booking = {
        equipmentId: equipment._id.toString(),
        equipmentName: equipment.name,
        equipmentImage: equipment.imageUrl || "",

        ownerId: equipment.ownerId,
        ownerName: equipment.ownerName || "",
        ownerEmail: equipment.ownerEmail || "",

        customerId: req.user.id,
        customerName: req.user.name || "",
        customerEmail: req.user.email.toLowerCase(),

        startDate: start,
        endDate: end,

        rentalDays,
        rentalUnits,
        rentalType: equipment.rentalType,

        quantity: requestedQuantity,

        unitPrice,
        totalAmount,
        currency,

        // Exact Stripe amount in cents
        stripeAmountTotal: stripeTotalAmount,

        contactNumber: contactNumber.trim(),
        deliveryAddress: deliveryAddress.trim(),
        additionalNotes: additionalNotes.trim(),

        paymentStatus: "pending",
        status: "pending",

        checkoutExpiresAt: expiresAt,
        stripeSessionId: null,

        createdAt: now,
        updatedAt: now,
      };

      const bookingResult = await bookingsCollection.insertOne(booking);

      bookingId = bookingResult.insertedId;

      // 11. Create Stripe Checkout Session
      const checkoutSession = await stripe.checkout.sessions.create({
        mode: "payment",

        customer_email: req.user.email,

        line_items: [
          {
            price_data: {
              currency: "usd",

              product_data: {
                name: equipment.name,

                description: `${rentalDays} day(s), ${requestedQuantity} item(s)`,

                ...(equipment.imageUrl ? { images: [equipment.imageUrl] } : {}),
              },

              // Example: $100 = 10000 cents
              unit_amount: stripeUnitAmount,
            },

            // Rental units × equipment quantity
            quantity: stripeQuantity,
          },
        ],

        metadata: {
          bookingId: bookingId.toString(),
          equipmentId: equipment._id.toString(),
          customerId: req.user.id,
        },

        expires_at: Math.floor(expiresAt.getTime() / 1000),

        success_url: `${frontendUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,

        cancel_url: `${frontendUrl}/equipment/${equipment._id.toString()}?payment=cancelled`,
      });

      // 12. Save Stripe session ID
      await bookingsCollection.updateOne(
        {
          _id: bookingId,
        },
        {
          $set: {
            stripeSessionId: checkoutSession.id,
            updatedAt: new Date(),
          },
        }
      );

      // 13. Send checkout URL to frontend
      return res.status(201).send({
        success: true,
        message: "Checkout session created successfully.",
        bookingId: bookingId.toString(),
        checkoutUrl: checkoutSession.url,
        totalAmount,
        currency,
      });
    } catch (error) {
      console.error("Create checkout error:", error);

      // Mark failed booking if Stripe session creation fails
      if (bookingId) {
        try {
          await bookingsCollection.updateOne(
            {
              _id: bookingId,
              paymentStatus: "pending",
            },
            {
              $set: {
                paymentStatus: "failed",
                status: "cancelled",
                updatedAt: new Date(),
              },
            }
          );
        } catch (updateError) {
          console.error("Booking failure update error:", updateError);
        }
      }

      return res.status(500).send({
        success: false,
        message: "Unable to create payment session.",
      });
    }
  }
);

// STRIPE WEBHOOK
// app.post("/api/stripe/webhook", async (req, res) => {
//   const signature = req.headers["stripe-signature"];
//   let event;
//   try {
//     event = stripe.webhooks.constructEvent(
//       req.rawBody,
//       signature,
//       process.env.STRIPE_WEBHOOK_SECRET
//     );
//   } catch (error) {
//     console.error("Stripe webhook signature error:", error.message);

//     return res.status(400).send({
//       success: false,
//       message: "Invalid Stripe webhook signature.",
//     });
//   }
//   try {
//     if (
//       event.type === "checkout.session.completed" ||
//       event.type === "checkout.session.async_payment_succeeded"
//     ) {
//       const session = event.data.object;

//       if (session.payment_status !== "paid") {
//         return res.status(200).send({ received: true });
//       }

//       const bookingId = session.metadata?.bookingId;

//       if (!bookingId || !ObjectId.isValid(bookingId)) {
//         console.error("Invalid booking ID in Stripe metadata.");
//         return res.status(200).send({ received: true });
//       }

//       const bookingObjectId = new ObjectId(bookingId);

//       const booking = await bookingsCollection.findOne({
//         _id: bookingObjectId,
//       });

//       if (!booking) {
//         console.error("Booking not found:", bookingId);
//         return res.status(200).send({ received: true });
//       }

//       // Idempotency: do not process an already-paid booking again.
//       if (booking.paymentStatus !== "paid") {
//         const paymentIntentId =
//           typeof session.payment_intent === "string"
//             ? session.payment_intent
//             : session.payment_intent?.id || null;

//         const transaction = {
//           bookingId: bookingId,
//           equipmentId: booking.equipmentId,
//           customerId: booking.customerId,
//           customerEmail: booking.customerEmail,

//           stripeSessionId: session.id,
//           stripePaymentIntentId: paymentIntentId,

//           amountTotal: session.amount_total,
//           currency: session.currency,

//           paymentStatus: "paid",
//           paymentMethod: "stripe",

//           createdAt: new Date(),
//           updatedAt: new Date(),
//         };

//         await paymentsCollection.updateOne(
//           { stripeSessionId: session.id },
//           {
//             $setOnInsert: transaction,
//           },
//           { upsert: true }
//         );

//         await bookingsCollection.updateOne(
//           {
//             _id: bookingObjectId,
//             paymentStatus: { $ne: "paid" },
//           },
//           {
//             $set: {
//               paymentStatus: "paid",
//               status: "confirmed",
//               stripeSessionId: session.id,
//               stripePaymentIntentId: paymentIntentId,
//               paidAt: new Date(),
//               updatedAt: new Date(),
//             },
//           }
//         );
//       }
//     }

//     if (event.type === "checkout.session.expired") {
//       const session = event.data.object;
//       const bookingId = session.metadata?.bookingId;

//       if (bookingId && ObjectId.isValid(bookingId)) {
//         await bookingsCollection.updateOne(
//           {
//             _id: new ObjectId(bookingId),
//             paymentStatus: "pending",
//           },
//           {
//             $set: {
//               paymentStatus: "expired",
//               status: "cancelled",
//               updatedAt: new Date(),
//             },
//           }
//         );
//       }
//     }

//     if (event.type === "checkout.session.async_payment_failed") {
//       const session = event.data.object;
//       const bookingId = session.metadata?.bookingId;

//       if (bookingId && ObjectId.isValid(bookingId)) {
//         await bookingsCollection.updateOne(
//           {
//             _id: new ObjectId(bookingId),
//             paymentStatus: "pending",
//           },
//           {
//             $set: {
//               paymentStatus: "failed",
//               status: "cancelled",
//               updatedAt: new Date(),
//             },
//           }
//         );
//       }
//     }

//     return res.status(200).send({ received: true });
//   } catch (error) {
//     console.error("Stripe webhook processing error:", error);

//     // Non-2xx response tells Stripe to retry the webhook.
//     return res.status(500).send({
//       success: false,
//       message: "Webhook processing failed.",
//     });
//   }
// });

// VERIFY STRIPE CHECKOUT PAYMENT — POST

app.post(
  "/api/payments/checkout-verify",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { sessionId } = req.body;

      // 1. Validate Stripe session ID
      if (!sessionId || typeof sessionId !== "string") {
        return res.status(400).send({
          success: false,
          message: "Valid Stripe session ID is required.",
        });
      }

      // 2. Retrieve actual Checkout Session from Stripe
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      const bookingId = session.metadata?.bookingId;
      const customerId = session.metadata?.customerId;

      if (!bookingId || !ObjectId.isValid(bookingId)) {
        return res.status(400).send({
          success: false,
          message: "Invalid booking information.",
        });
      }

      // 3. Verify customer ownership
      if (customerId !== req.user.id) {
        return res.status(403).send({
          success: false,
          message: "You cannot verify this payment.",
        });
      }

      // 4. Find booking belonging to this customer
      const booking = await bookingsCollection.findOne({
        _id: new ObjectId(bookingId),
        customerId: req.user.id,
      });

      if (!booking) {
        return res.status(404).send({
          success: false,
          message: "Booking not found.",
        });
      }

      // 5. Verify Checkout Session ownership
      if (booking.stripeSessionId !== session.id) {
        return res.status(409).send({
          success: false,
          message: "Checkout session does not match this booking.",
        });
      }

      // 6. Verify payment completion
      if (
        session.mode !== "payment" ||
        session.status !== "complete" ||
        session.payment_status !== "paid"
      ) {
        return res.status(409).send({
          success: false,
          message: "Payment is not completed yet.",
        });
      }

      // 7. Verify exact amount and currency
      const expectedAmount = booking.stripeAmountTotal;

      if (!Number.isSafeInteger(expectedAmount) || expectedAmount <= 0) {
        return res.status(400).send({
          success: false,
          message: "Invalid booking payment amount.",
        });
      }

      if (
        session.amount_total !== expectedAmount ||
        session.currency !== "usd" ||
        booking.currency !== "usd"
      ) {
        return res.status(409).send({
          success: false,
          message: "Payment amount or currency does not match.",
        });
      }

      // 8. Get Payment Intent ID
      const paymentIntentId =
        typeof session.payment_intent === "string"
          ? session.payment_intent
          : session.payment_intent?.id || null;

      const now = new Date();

      // 9. Check whether payment was already verified
      if (booking.paymentStatus === "paid") {
        return res.status(200).send({
          success: true,
          message: "Payment already verified.",
          bookingId: booking._id.toString(),
          paymentStatus: "paid",
        });
      }

      // 10. Update booking only once
      const bookingUpdate = await bookingsCollection.updateOne(
        {
          _id: booking._id,
          customerId: req.user.id,
          stripeSessionId: session.id,
          paymentStatus: "pending",
        },
        {
          $set: {
            paymentStatus: "paid",
            status: "confirmed",
            stripePaymentIntentId: paymentIntentId,
            paidAt: now,
            updatedAt: now,
          },
        }
      );

      if (bookingUpdate.modifiedCount !== 1) {
        const latestBooking = await bookingsCollection.findOne({
          _id: booking._id,
          customerId: req.user.id,
        });

        if (latestBooking?.paymentStatus === "paid") {
          return res.status(200).send({
            success: true,
            message: "Payment already verified.",
            bookingId: booking._id.toString(),
            paymentStatus: "paid",
          });
        }

        return res.status(409).send({
          success: false,
          message: "Booking could not be updated. Please try again.",
        });
      }

      // 11. Save payment transaction
      // Upsert prevents duplicate transaction records.
      await paymentsCollection.updateOne(
        {
          stripeSessionId: session.id,
        },
        {
          $setOnInsert: {
            bookingId: booking._id.toString(),
            equipmentId: booking.equipmentId,
            customerId: booking.customerId,
            customerEmail: booking.customerEmail,

            stripeSessionId: session.id,
            stripePaymentIntentId: paymentIntentId,

            amountTotal: session.amount_total,
            currency: session.currency,

            paymentStatus: "paid",
            paymentMethod: "stripe",

            createdAt: now,
          },

          $set: {
            updatedAt: now,
          },
        },
        {
          upsert: true,
        }
      );

      // 12. Send success response
      return res.status(200).send({
        success: true,
        message: "Payment verified successfully.",
        bookingId: booking._id.toString(),
        paymentStatus: "paid",
      });
    } catch (error) {
      console.error("Payment verification error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to verify payment.",
      });
    }
  }
);

// GET BOOKING DETAILS — CUSTOMER
app.get("/api/bookings/:id", verifyToken, verifyCustomer, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid booking ID.",
      });
    }
    const booking = await bookingsCollection.findOne({
      _id: new ObjectId(id),
      customerId: req.user.id,
    });

    if (!booking) {
      return res.status(404).send({
        success: false,
        message: "Booking not found.",
      });
    }

    return res.status(200).send({
      success: true,
      booking: {
        ...booking,
        _id: booking._id.toString(),
      },
    });
  } catch (error) {
    console.error("Get booking error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to fetch booking.",
    });
  }
});

// Admin Analytics

app.get("/api/admin/analytics", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalEquipment,
      totalBookings,
      pendingApprovals,
      completedRentals,
      revenueResult,
      monthlyBookings,
    ] = await Promise.all([
      // Total users
      usersCollection.countDocuments(),

      // Total equipment
      equipmentCollection.countDocuments(),

      // Total bookings
      bookingsCollection.countDocuments(),

      // Pending equipment approvals
      equipmentCollection.countDocuments({
        status: "pending",
      }),

      // Completed and paid rentals
      bookingsCollection.countDocuments({
        status: "completed",
        paymentStatus: "paid",
      }),

      // Total successful revenue (Stripe stores USD cents)
      paymentsCollection
        .aggregate([
          {
            $match: {
              paymentStatus: "paid",
            },
          },
          {
            $group: {
              _id: null,
              totalCents: {
                $sum: "$amountTotal",
              },
            },
          },
        ])
        .toArray(),

      // Monthly booking statistics
      bookingsCollection
        .aggregate([
          {
            $match: {
              createdAt: { $type: "date" },
            },
          },
          {
            $group: {
              _id: {
                year: {
                  $year: "$createdAt",
                },
                month: {
                  $month: "$createdAt",
                },
              },
              totalBookings: {
                $sum: 1,
              },
            },
          },
          {
            $sort: {
              "_id.year": 1,
              "_id.month": 1,
            },
          },
        ])
        .toArray(),
    ]);

    // Convert Stripe cents to USD
    const totalRevenue = (revenueResult[0]?.totalCents || 0) / 100;

    return res.status(200).send({
      success: true,
      analytics: {
        totalUsers,
        totalEquipment,
        totalBookings,
        pendingApprovals,
        completedRentals,
        totalRevenue,
        currency: "USD",

        monthlyBookings: monthlyBookings.map((item) => ({
          year: item._id.year,
          month: item._id.month,
          totalBookings: item.totalBookings,
        })),
      },
    });
  } catch (error) {
    console.error("Admin analytics error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to load admin analytics",
    });
  }
});

// Owner Analytics get api
app.get("/api/owner/analytics", verifyToken, verifyOwner, async (req, res) => {
  try {
    const ownerId = req.user.id;

    // Reusable payment lookup pipeline
    const ownerPaymentPipeline = [
      {
        $match: {
          paymentStatus: "paid",
        },
      },
      {
        $addFields: {
          bookingObjectId: {
            $convert: {
              input: "$bookingId",
              to: "objectId",
              onError: null,
              onNull: null,
            },
          },
        },
      },
      {
        $lookup: {
          from: "bookings",
          localField: "bookingObjectId",
          foreignField: "_id",
          as: "booking",
        },
      },
      {
        $unwind: "$booking",
      },
      {
        $match: {
          "booking.ownerId": ownerId,
        },
      },
    ];

    const [
      totalListedEquipment,
      completedRentals,
      earningsResult,
      monthlyEarnings,
    ] = await Promise.all([
      // Total equipment listed by this owner
      equipmentCollection.countDocuments({
        ownerId,
      }),

      // Completed and paid rentals
      bookingsCollection.countDocuments({
        ownerId,
        status: "completed",
        paymentStatus: "paid",
      }),

      // Total owner earnings
      paymentsCollection
        .aggregate([
          ...ownerPaymentPipeline,
          {
            $group: {
              _id: null,
              totalCents: {
                $sum: "$amountTotal",
              },
            },
          },
        ])
        .toArray(),

      // Monthly owner earnings
      paymentsCollection
        .aggregate([
          ...ownerPaymentPipeline,
          {
            $match: {
              createdAt: {
                $type: "date",
              },
            },
          },
          {
            $group: {
              _id: {
                year: {
                  $year: "$createdAt",
                },
                month: {
                  $month: "$createdAt",
                },
              },
              earningsCents: {
                $sum: "$amountTotal",
              },
            },
          },
          {
            $sort: {
              "_id.year": 1,
              "_id.month": 1,
            },
          },
        ])
        .toArray(),
    ]);

    // Convert cents to USD
    const totalEarnings = (earningsResult[0]?.totalCents || 0) / 100;

    return res.status(200).send({
      success: true,
      analytics: {
        totalListedEquipment,
        completedRentals,
        totalEarnings,
        currency: "USD",

        monthlyEarnings: monthlyEarnings.map((item) => ({
          year: item._id.year,
          month: item._id.month,
          earnings: item.earningsCents / 100,
        })),
      },
    });
  } catch (error) {
    console.error("Owner analytics error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to load owner analytics",
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
