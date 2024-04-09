import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
dotenv.config();

app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.DATABASE,
  password: process.env.DATABASE_PASSWORD,
  port: 5432,
});

db.connect()
  .then(() => {
    console.log('Connected to database');
  })
  .catch(err => {
    console.error('Error connecting to database:', err);
  });


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/main", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("main.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get('/auth/google', passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get('/auth/google/main', 
passport.authenticate("google",{
  successRedirect:'/main',
  failureRedirect:'/login',
}));

app.post("/login",
 passport.authenticate("local", {
  successRedirect: "/main",
  failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM logins WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO logins (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Error logging in:", err);
              res.redirect("/login");
            } else {
              res.redirect("/main");
            }
          });
        }
      });
    }
  } catch (err) {
    console.error("Error during registration:", err);
    res.redirect("/register");
  }
});

passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM logins WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false, { message: 'Invalid password' });
            }
          }
        });
      } else {
        return cb(null, false, { message: 'User not found' });
      }
    } catch (err) {
      console.error("Error in local strategy:", err);
      return cb(err);
    }
  })
);

passport.use(
  "google", 
  new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/main",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async(accessToken, refreshToken, profile, cb) => {
  try {
    console.log(profile);
    const result = await db.query("SELECT * FROM logins WHERE email = $1", [
      profile.email,
    ]);
    if (result.rows.length === 0) {
      const newUser = await db.query(
        "INSERT INTO logins (email, password) VALUES ($1, $2)",
        [profile.email, "google"]
      );
      return cb(null, newUser.rows[0]);
    } else {
      return cb(null, result.rows[0]);
    }
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
