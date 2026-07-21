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


// Only allows users with the correct token.
function protect(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send("Not authorized, no token");
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).send("Not authorized, invalid token");
  }
}

//register
e.post("/api/auth/register", async function (req, res) {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.send("Name, email and password are required"); // check empty fields
  }

  const existing = await User.findOne({ email });
  if (existing) {
    return res.send("Email already registered"); // check duplicate email
  }

  const hashedPassword = await bcrypt.hash(password, 10); // hash password
  const user = new User({
    name,
    email,
    password: hashedPassword,
    role: role === "admin" ? "admin" : "user",
  });
  await user.save();

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" }); // create login token
  res.send({ name: user.name, email: user.email, role: user.role, token });
});

//login
e.post("/api/auth/login", async function (req, res) {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.send("Invalid email or password");

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.send("Invalid email or password");

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "7d" });
  res.send({ name: user.name, email: user.email, role: user.role, token });
});

//get logged in user
e.get("/api/auth/me", protect, async function (req, res) {
  const user = await User.findById(req.userId); // find user from token
  res.send(user);
});

// Gets all students
e.get("/api/students", protect, async function (req, res) {
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
  res.send({ data: students, total, page: Number(page), pages: Math.ceil(total / limit) });
});

//get one student
e.get("/api/students/:id", protect, async function (req, res) {
  const student = await Student.findById(req.params.id);
  if (!student) return res.send("Student not found");
  res.send(student);
});

//add student
e.post("/api/students", protect, async function (req, res) {
  const { fullName, studentId, email, course } = req.body;
  if (!fullName || !studentId || !email || !course) {
    return res.send("Full name, student ID, email and course are required");
  }

  const existing = await Student.findOne({ studentId });
  if (existing) return res.send("Student ID already exists");

  const student = new Student({ ...req.body, createdBy: req.userId });
  await student.save();
  res.send(student);
});

//update student
e.put("/api/students/:id", protect, async function (req, res) {
  const student = await Student.findByIdAndUpdate(req.params.id, req.body, { new: true });
  if (!student) return res.send("Student not found");
  res.send(student);
});

//delete student
e.delete("/api/students/:id", protect, async function (req, res) {
  const student = await Student.findByIdAndDelete(req.params.id);
  if (!student) return res.send("Student not found");
  res.send("Student deleted");
});

//health check
e.get("/api/health", function (req, res) {
  res.send("ok");
});