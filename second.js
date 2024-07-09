const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.put('/update-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;

    const user = getUserFromDatabase(userId);

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
        return res.status(400).json({ message: 'Incorrect old password' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    updateUserInDatabase(user);

    res.status(200).json({ message: 'Password updated successfully' });
});

function getUserFromDatabase(userId) {
    return {
        id: userId,
        password: '$2a$10$7aPovrUuKn/fF3WjlXaDPe/fjPZzH57L6.8ob2wJfGJbLRPzRBiEq'
    };
}

function updateUserInDatabase(user) {
    console.log('User updated in the database:', user);
}

app.listen(port, () => {
    console.log(`Server is running on ${port}`);
});
