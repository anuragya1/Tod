const mongoose = require('mongoose');

// Define TodoTask Schema
const todoTaskSchema = new mongoose.Schema({
  content: {
    type: String,
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  priority: {
    type: String,
    enum: ['Low', 'Medium', 'High'], // You can change this to numbers if you prefer
    default: 'Medium', // Default priority is Medium
  },
});

const TodoTask = mongoose.model('TodoTask', todoTaskSchema);

module.exports = TodoTask;
