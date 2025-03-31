import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from './models/User.js';
import Transaction from './models/Transaction.js';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid Token' });
    }
};

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, balance: 0 });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
});

app.get('/balance', authMiddleware, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json({ balance: user.balance });
});

app.post('/add-money', authMiddleware, async (req, res) => {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);
    user.balance += amount;
    await user.save();
    const transaction = new Transaction({ userId: user._id, type: 'credit', amount });
    await transaction.save();
    res.json({ message: 'Money added successfully', balance: user.balance });
});

app.post('/transfer', authMiddleware, async (req, res) => {
    const { recipientEmail, amount } = req.body;
    const sender = await User.findById(req.user.id);
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) return res.status(400).json({ message: 'Recipient not found' });
    if (sender.balance < amount) return res.status(400).json({ message: 'Insufficient balance' });
    sender.balance -= amount;
    recipient.balance += amount;
    await sender.save();
    await recipient.save();
    const transaction = new Transaction({ userId: sender._id, type: 'debit', amount, recipient: recipient._id });
    await transaction.save();
    res.json({ message: 'Transfer successful', balance: sender.balance });
});

app.listen(5000, () => console.log('Server running on port 5000'));
