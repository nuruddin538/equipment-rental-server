import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";

const app = express();
const port = process.env.PORT || 5000;

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

const db = client.db(process.env.MONGODB_DB_NAME || "equipment-rental");

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
