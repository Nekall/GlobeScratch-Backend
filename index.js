import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
dotenv.config();
import Airtable from "airtable";
const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(
  process.env.AIRTABLE_BASE_ID
);

const PORT = process.env.PORT || 3001;

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.get("/", async (_, res) => {
  res.send("GlobeScratch API is running...");
});

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, lastname, firstname, country } =
      req.body;
    if (
      !username ||
      !email ||
      !password ||
      !lastname ||
      !firstname ||
      !country
    ) {
      return res
        .status(400)
        .json({ message: "Veuillez remplir tous les champs requis." });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await base.table("users").create([
      {
        fields: {
          username,
          email,
          password: hashedPassword,
          firstname,
          lastname,
          country,
        },
      },
    ]);

    res.status(200).json({ message: "Compte créé avec succès." });
  } catch (error) {
    console.error("Erreur lors de la création du compte:", error);
    res
      .status(500)
      .json({
        message: "Une erreur est survenue lors de la création du compte.",
      });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = {
    email,
  };

  let token = jwt.sign({ user });
  res.send(token);
});

app.listen(PORT, () => {
  console.log(`server is ready on port: http://localhost:${PORT}`);
});
