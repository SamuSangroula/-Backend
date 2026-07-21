import mongoose from 'mongoose';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

mongoose.connect(process.env.MONGO_URI);

const e = express();
const SECRET = process.env.JWT_SECRET;
e.use(cors());
e.use(express.json());

e.listen(5000);
console.log("Hi")

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: { type: String, default: "user" },
});
const User = mongoose.model("User", userSchema);

const studentSchema = new mongoose.Schema({
  fullName: String,
  studentId: String,
  email: String,
  phone: String,
  dateOfBirth: Date,
  course: String,
  yearOrSemester: String,
  address: String,
  guardianName: String,
  guardianContact: String,
  enrollmentDate: { type: Date, default: Date.now },
  status: { type: String, default: "active" },
  createdBy: String,
}, { timestamps: true });
const Student = mongoose.model("Student", studentSchema);

function protect(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Not authorized, no token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Not authorized, invalid token" });
  }
}

e.post("/api/auth/register", async function (req, res) {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email and password are required" });
    }
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already registered" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role: role === "admin" ? "admin" : "user" });
    await user.save();
    const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
    res.status(201).json({ _id: user._id, name: user.name, email: user.email, role: user.role, token });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

e.post("/api/auth/login", async function (req, res) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid email or password" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid email or password" });
    const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
    res.json({ _id: user._id, name: user.name, email: user.email, role: user.role, token });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

e.get("/api/auth/me", protect, async function (req, res) {
  const user = await User.findById(req.userId);
  res.json(user);
});

e.get("/api/students", protect, async function (req, res) {
  try {
    const { search, status, page = 1, limit = 10 } = req.query;
    const query = {};
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: "i" } },
        { studentId: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
      ];
    }
    if (status) query.status = status;
    const students = await Student.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit));
    const total = await Student.countDocuments(query);
    res.json({ data: students, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

e.get("/api/students/:id", protect, async function (req, res) {
  const student = await Student.findById(req.params.id);
  if (!student) return res.status(404).json({ message: "Student not found" });
  res.json(student);
});

e.post("/api/students", protect, async function (req, res) {
  try {
    const { fullName, studentId, email, course } = req.body;
    if (!fullName || !studentId || !email || !course) {
      return res.status(400).json({ message: "Full name, student ID, email and course are required" });
    }
    const existing = await Student.findOne({ studentId });
    if (existing) return res.status(400).json({ message: "Student ID already exists" });
    const student = new Student({ ...req.body, createdBy: req.userId });
    await student.save();
    res.status(201).json(student);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

e.put("/api/students/:id", protect, async function (req, res) {
  try {
    const student = await Student.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!student) return res.status(404).json({ message: "Student not found" });
    res.json(student);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

e.delete("/api/students/:id", protect, async function (req, res) {
  const student = await Student.findByIdAndDelete(req.params.id);
  if (!student) return res.status(404).json({ message: "Student not found" });
  res.json({ message: "Student deleted" });
});

e.get("/api/health", function (req, res) {
  res.json({ status: "ok" });
});