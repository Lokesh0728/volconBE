import express from "express";
import profiles from "../models/profiles.js"; // your schema model
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const router = express.Router();

// ----------------------------
// REGISTER
// ----------------------------
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, phone, state, pincode, address } = req.body;

    // Check missing fields
    if (
      !name ||
      !email ||
      !password ||
      !phone ||
      !state ||
      !pincode ||
      !address
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check user exists
    const existing = await profiles.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create profile
    const newUser = await profiles.create({
      name,
      email,
      password: hashedPassword,
      phone,
      state,
      pincode,
      address,
    });

    res.status(201).json({
      message: "User registered successfully",
      user: newUser,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ----------------------------
// LOGIN
// ----------------------------
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await profiles.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email" });

    const passMatch = await bcrypt.compare(password, user.password);
    if (!passMatch)
      return res.status(400).json({ message: "Invalid password" });

    // Generate Access Token
    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    // Generate Refresh Token
    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "2d" }
    );

    // Save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save();

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        imageUrl: user.imageUrl,
        phone: user.phone,
        state: user.state,
        pincode: user.pincode,
        address: user.address,
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ----------------------------
// UPDATE PROFILE (phone, pincode, state, address INCLUDED)
// ----------------------------
router.put("/update/:id", async (req, res) => {
  try {
    const { name, phone, state, pincode, address, imageUrl } = req.body;

    const updated = await profiles.findByIdAndUpdate(
      req.params.id,
      { name, phone, state, pincode, address, imageUrl },
      { new: true }
    );

    if (!updated) return res.status(404).json({ message: "User not found" });

    res.json({
      message: "Profile updated",
      updated,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ----------------------------
// GET PROFILE (single)
// ----------------------------
router.get("/:id", async (req, res) => {
  try {
    const user = await profiles.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ----------------------------
// GET ALL PROFILES
// ----------------------------
router.get("/", async (req, res) => {
  try {
    const all = await profiles.find();
    res.json(all);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

export default router;
