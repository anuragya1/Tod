const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  githubId: { type: String, required: true },
  username: { type: String, required: true },
  email: { type: String, required: true }, // Ensure email is required
  password: { type: String, required: false }, // Make password optional
});

const User = mongoose.model('User', userSchema);

module.exports = User;
