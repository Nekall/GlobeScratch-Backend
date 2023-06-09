import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
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
    const { email, password, lastname, firstname, country } =
      req.body;
    if (
      !email ||
      !password ||
      !lastname ||
      !firstname ||
      !country
    ) {
      return res
        .status(400)
        .json({ 
          success: false,
          message: "Veuillez remplir tous les champs requis." });
    }

    const user = await base("users")
      .select({
        filterByFormula: `{email} = "${email}"`,
      })
      .all();
    
    if(user.length > 0) {
      return res
        .status(409)
        .json({ 
          success: false,
          message: "Un utilisateur existe déjà avec cet email." });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await base.table("users").create([
      {
        fields: {
          email,
          password: hashedPassword,
          firstname,
          lastname,
          country,
        },
      },
    ]);

    res.status(200).json({ 
      success: true,
      message: "Compte créé avec succès." });
  } catch (error) {
    console.error("Erreur lors de la création du compte:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Une erreur est survenue lors de la création du compte.",
      });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res
      .status(400)
      .json({ 
        success: false,
        message: "Veuillez remplir tous les champs requis." });
  
  let user = base("users")
    .select({
      filterByFormula: `{email} = "${email}"`,
    })
    .all((err, records) => {
      if(err) {
        console.error("Erreur lors de la récupération de l'utilisateur:", err);
        return res
          .status(500)
          .json({
            success: false,
            message: "Une erreur est survenue lors de la récupération de l'utilisateur.",
          });
      }
      if(records.length === 0) {
        return res
          .status(404)
          .json({
            success: false,
            message: "Aucun utilisateur trouvé avec cet email.",
          });
      }
      const user = records[0].fields;
      bcrypt.compare(password, user.password, (err, result) => {
        if(err) {
          console.error("Erreur lors de la comparaison des mots de passe:", err);
          return res
            .status(500)
            .json({
              success: false,
              message: "Une erreur est survenue lors de la comparaison des mots de passe.",
            });
        }
        if(!result) {
          return res
            .status(401)
            .json({
              success: false,
              message: "Mot de passe incorrect.",
            });
        }

        delete user.password;
        const token = jwt.sign({ user }, process.env.JWT_SECRET, {
          expiresIn: "30d",
        });
        res
          .status(200)
          .json({
            success: true,
            message: "Connexion réussie.",
            token,
            user,
            });
      
      });
    });
});

app.listen(PORT, () => {
  console.log(`server is ready on port: http://localhost:${PORT}`);
});
