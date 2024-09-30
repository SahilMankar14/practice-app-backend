require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGODB_URI;

const app = express();

app.use(express.json());

const corsOptions = {
  origin: "*",
  exposedHeaders: ["Authorization"], // Expose Authorization header
};
app.use(cors(corsOptions));

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("Connected to MongoDB Atlas");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });

const userSchema = new mongoose.Schema({
  fullName: String,
  lastName: String,
  middleName: String,
  name: String,
  age: Number,
  email: String,
  password: String,
  confirmPassword: String,
  dateOfBirth: String,
  gender: String,
  mobileno: String,
  role: String,
  profilePhoto: {
    data: Buffer,
    contentType: String,
  },
});

const User = mongoose.model("User", userSchema);

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 16 * 1024 * 1024 }, // 16MB limit
});

app.post("/signup", upload.single("profilePhoto"), async (req, res) => {
  try {
    const userData = req.body;
    console.log("userData:", userData);

    const hashPassword = await bcrypt.hash(userData.password, 5);

    userData.password = hashPassword;

    if (req.file) {
      userData.profilePhoto = {
        data: req.file.buffer,
        contentType: req.file.mimetype,
      };
    }

    const user = new User(userData);
    await user.save();
    res.status(201).send("User data saved successfully!");
  } catch (error) {
    console.error("Error saving data:", error);
    res.status(500).send("Error saving data");
  }
});

app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email, password: password });

    if (user) {
      const token = jwt.sign(
        {
          username: user.email,
        },
        JWT_SECRET
      );
      res.setHeader("Authorization", `Bearer ${token}`);
      res.status(200).send("User authenticated");
    } else {
      res.status(401).send("Invalid email or password");
    }
  } catch (error) {
    console.error("Error during sign-in:", error);
    res.status(500).send("Internal server error");
  }
});

function auth(req, res, next) {
  const token = req.headers.authorization.split(" ")[2];

  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid User or Token expired" });
  }
}

app.get("/get-user-data", auth, async (req, res) => {
  try {
    const users = await User.find({}, "-password -confirmPassword");
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send("Error fetching users");
  }
});

app.get("/user/:id/profilePhoto", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user && user.profilePhoto) {
      res.contentType(user.profilePhoto.contentType);
      res.send(user.profilePhoto.data);
    } else {
      res.status(404).send("Not found");
    }
  } catch (error) {
    console.error("Error fetching profile photo:", error);
    res.status(500).send("Error fetching profile photo");
  }
});

app.get("/", (req, res) => res.send("Express on Vercel"));

app.listen(3000, () => console.log("Server ready on port 3000."));

module.exports = app;
