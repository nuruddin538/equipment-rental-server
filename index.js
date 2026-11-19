import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

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
app.use(express.json());

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
