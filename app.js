const express = require('express');
const { sql, poolPromise } = require("./db");
const bcrypt = require("bcrypt");

require("dotenv").config();

const jwt = require("jsonwebtoken");

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));




app.get("/", async (req, res) => {
    try {
        const pool = await poolPromise;

        const result = await pool.request().query("SELECT 1 AS test");

        console.log(result.recordset);

        res.send("Database connected!");
    } catch (error) {
        console.log(error);
        res.status(500).send("Database connection failed");
    }
});


app.get('/signup', (req, res)=>{
    res.render("signup", { error: null });
});


app.post('/signup', async (req, res)=>{
    const {email, password} = req.body;

    try{
        const pool = await poolPromise;

        const result = await pool.request()
            .input("email", sql.NVarChar, email)
            .query("SELECT * FROM Users WHERE Email = @email");

        const existingUser = result.recordset[0];

        if (existingUser) {
            return res.render("signup", {
                error: "User already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.request()
            .input("email", sql.NVarChar, email)
            .input("password", sql.NVarChar, hashedPassword)
            .query(`
                INSERT INTO Users (Email, PasswordHash)
                VALUES (@email, @password)
            `);

        res.redirect('/login');

    } catch (error) {
        console.log(error);
        res.status(500).send("Something went wrong");
    }
});


app.get("/login", (req, res)=>{
    res.render("login", { error: null });
});


app.post("/login", async (req, res)=>{
    const {email, password} = req.body;

    try{
        const pool = await poolPromise;

        const result = await pool.request()
            .input("email", sql.NVarChar, email)
            .query("SELECT * FROM Users WHERE Email = @email");

        const user = result.recordset[0];

        if (!user) {
            return res.render("login", {
                error: "Invalid email or password"
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.PasswordHash
        );

        if (passwordMatch) {

            const token = jwt.sign(
                { userId: user.Id },
                JWT_SECRET,
                { expiresIn: "30d" }
            );

            res.json({ token });

        } else {
            res.status(401).send("Invalid email or password");
        }

    } catch (error) {
        console.log(error);
        res.status(500).send("Something went wrong");
    }
});



function requireJWT(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send("Access denied");
    }

    const token = authHeader.split(" ")[1];

    try {

        const decoded = jwt.verify(token, JWT_SECRET);

        req.userId = decoded.userId;

        next();

    } catch (error) {
        res.status(401).send("Invalid or expired token");
    }
}


app.get("/home", requireJWT, async (req, res) => {

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input("id", sql.Int, req.userId)
            .query("SELECT * FROM Users WHERE Id = @id");

        const user = result.recordset[0];

        if (!user) {
            return res.status(404).send("User not found");
        }

        res.render("home", { user });

    } catch (error) {
        console.error(error);
        res.status(500).send("Server error");
    }
});




app.get("/jwt-test", requireJWT, (req, res)=>{

    res.send(`You are user ${req.userId}`);
});


app.listen(3000, ()=>{
    console.log("Server running at http://localhost:3000");
});