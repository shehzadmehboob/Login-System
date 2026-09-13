require("dotenv").config();

const express = require("express");
const { sql, poolPromise } = require("./db");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { randomInt } = require("crypto");
const transporter = require("./mailer");
const session = require("express-session");
const jwt = require("jsonwebtoken");

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false
    })
);

app.get("/", async (req, res) => {

    try {

        const pool = await poolPromise;

        const result = await pool.request()
            .query("SELECT 1 AS test");

        console.log(result.recordset);

        res.send("Database connected!");

    } catch (error) {

        console.log(error);

        res.status(500).send("Database connection failed");

    }

});

app.get("/signup", (req, res) => {

    res.render("signup", {
        error: null
    });

});


app.post("/signup", async (req, res) => {

    const { email, password } = req.body;

    try {

        const pool = await poolPromise;

        const result = await pool.request()
            .input("email", sql.NVarChar, email)
            .query(`
                SELECT *
                FROM Users
                WHERE Email = @email
            `);


        const existingUser = result.recordset[0];

        if (existingUser) {

            if (existingUser.IsVerified) {

                return res.render("signup", {
                    error: "User already exists"
                });

            }

            const code = randomInt(100000, 1000000);


            req.session.verificationUserId = existingUser.Id;
            req.session.verificationCode = code;


            await transporter.sendMail({

                from: process.env.EMAIL,

                to: email,

                subject: "Email verification code",

                text: `Your verification code is ${code}`

            });

            return res.redirect("/verify");

        }


        const hashedPassword = await bcrypt.hash(password, 10);

        const insertResult = await pool.request()
            .input("email", sql.NVarChar, email)
            .input("password", sql.NVarChar, hashedPassword)
            .query(`
                INSERT INTO Users (Email, PasswordHash)
                OUTPUT INSERTED.Id
                VALUES (@email, @password)
            `);

        const userId = insertResult.recordset[0].Id;

        const code = randomInt(100000, 1000000);

        req.session.verificationUserId = userId;
        req.session.verificationCode = code;

        await transporter.sendMail({

            from: process.env.EMAIL,
            to: email,
            subject: "Email verification code",
            text: `Your verification code is ${code}`

        });

        res.redirect("/verify");


    } catch (error) {

        console.log(error);

        res.status(500).send("Something went wrong");

    }

});

app.get("/verify", (req, res) => {

    res.render("verify", {
        error: null
    });

});


app.post("/verify", async (req, res) => {

    const enteredCode = Number(req.body.code);

    if (
        !req.session.verificationCode ||
        !req.session.verificationUserId
    ) {

        return res.status(400).send(
            "Verification session expired"
        );

    }


    if (enteredCode !== req.session.verificationCode) {

        return res.render("verify", {
            error: "Wrong verification code"
        });

    }


    try {

        const pool = await poolPromise;

        await pool.request()
            .input(
                "id",
                sql.Int,
                req.session.verificationUserId
            )
            .query(`
                UPDATE Users
                SET IsVerified = 1
                WHERE Id = @id
            `);


        delete req.session.verificationCode;
        delete req.session.verificationUserId;


        res.redirect("/login");


    } catch (error) {

        console.log(error);

        res.status(500).send("Something went wrong");

    }

});

app.get("/login", (req, res) => {

    res.render("login", {
        error: null
    });

});


app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    try {

        const pool = await poolPromise;

        const result = await pool.request()
            .input("email", sql.NVarChar, email)
            .query(`
                SELECT *
                FROM Users
                WHERE Email = @email
            `);


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

        if (!passwordMatch) {

            return res.render("login", {
                error: "Invalid email or password"
            });

        }


        if (!user.IsVerified) {

            return res.render("login", {
                error: "Please verify your email before logging in"
            });

        }

        const token = jwt.sign(
            {
                userId: user.Id,
            },

            JWT_SECRET,

            {
                expiresIn: "30d"
            }
        );


        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.redirect("/home");

    } catch (error) {
        console.log(error);
        res.status(500).send("Something went wrong");

    }

});

function requireJWT(req, res, next) {

    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send("Access denied");
    }

        try {
            const decoded = jwt.verify(
                token,
                JWT_SECRET
            );

            req.userId = decoded.userId;

            next();


        } catch (error) {

            res.status(401).send(
                "Invalid or expired token"
            );

        }

}

app.get("/home", requireJWT, async (req, res) => {

    try {

        const pool = await poolPromise;

        const result = await pool.request()
            .input(
                "id",
                sql.Int,
                req.userId
            )
            .query(`
                SELECT *
                FROM Users
                WHERE Id = @id
            `);

        const user = result.recordset[0];
        if (!user) {

            return res.status(404).send(
                "User not found"
            );

        }

        res.render("home", {
            user
        });


    } catch (error) {
        console.error(error);
        res.status(500).send(
            "Server error"
        );
    }
});


app.get("/logout", (req, res) => {

    res.clearCookie("token");

    res.redirect("/login");

});

app.get("/jwt-test", requireJWT, (req, res) => {

    res.send(
        `You are user ${req.userId}`
    );

});

app.listen(3000, () => {

    console.log(
        "Server running at http://localhost:3000"
    );

});