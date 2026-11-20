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
