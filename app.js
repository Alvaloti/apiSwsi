import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import User from "./model/User.js";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser"; // Importar cookie-parser
import Area from "./model/Area.js";
import Category from "./model/Categoria.js";
import Role from "./model/Role.js";
import Inventario from "./model/Inventario.js";
import Solicitud from "./model/Solicitud.js";
import Ticket from "./model/Ticket.js";
import Asignacion from "./model/Asignacion.js";
import ESTADOS from "./model/Estados.js";
const noCache = (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
};

dotenv.config();

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:4200", // Angular frontend URL
    credentials: true, // Permitir cookies
  }),
);
app.use(cookieParser()); // Middleware para parsear cookies

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/swsi";
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

const authenticate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ status: "error", message: "No autorizado" });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).userId;
    next();
  } catch {
    res.clearCookie("token", { path: "/", httpOnly: true, sameSite: "lax" });
    return res.status(401).json({ status: "error", message: "Sesión inválida o expirada" });
  }
};

const authorizeRoles = (...allowedRoles) => async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).populate("rolId", "name");
    const role = String(user?.rolId?.name || "").toLowerCase();
    const allowed = allowedRoles.map((item) => item.toLowerCase());
    if (!user || !allowed.includes(role)) {
      return res.status(403).json({ status: "error", message: "No tienes permisos para realizar esta acción" });
    }
    next();
  } catch {
    return res.status(403).json({ status: "error", message: "No fue posible validar tus permisos" });
  }
};

const adminOnly = authorizeRoles("admin", "administrador");
const supportStaff = authorizeRoles("admin", "administrador", "supervisor", "tecnico", "técnico");
const authorizeWorkItemUpdate = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).populate("rolId", "name");
    const role = String(user?.rolId?.name || "").toLowerCase();
    const supportRoles = ["admin", "administrador", "supervisor", "tecnico", "técnico"];
    if (!user || !supportRoles.includes(role)) {
      return res.status(403).json({ status: "error", message: "No tienes permisos para realizar esta acción" });
    }
    if (Object.prototype.hasOwnProperty.call(req.body, "estado") && !["tecnico", "técnico"].includes(role)) {
      return res.status(403).json({
        status: "error",
        message: "Solo un técnico puede modificar el estado de solicitudes y tickets",
      });
    }
    if (Object.prototype.hasOwnProperty.call(req.body, "tecnico_id")) {
      if (role !== "supervisor") {
        return res.status(403).json({
          status: "error",
          message: "Solo un supervisor puede asignar técnicos a solicitudes y tickets",
        });
      }
      const technician = await User.findById(req.body.tecnico_id).populate("rolId", "name active");
      const technicianRole = String(technician?.rolId?.name || "").toLowerCase();
      if (!technician || technician.active === false || technician.rolId?.active === false || !["tecnico", "técnico"].includes(technicianRole)) {
        return res.status(400).json({
          status: "error",
          message: "El usuario seleccionado no es un técnico activo",
        });
      }
    }
    next();
  } catch {
    return res.status(403).json({ status: "error", message: "No fue posible validar tus permisos" });
  }
};
const adminOrFirstUser = async (req, res, next) => {
  if ((await User.countDocuments()) === 0) return next();
  authenticate(req, res, () => adminOnly(req, res, next));
};

const getId = (req) => req.params.id;
const notFound = (res, resource) =>
  res.status(404).json({ status: "error", message: `${resource} no encontrado` });

const pick = (source, fields) =>
  Object.fromEntries(fields.filter((field) => source[field] !== undefined).map((field) => [field, source[field]]));

const registerCrudRoutes = (
  path,
  Model,
  fields,
  label,
  editAuthorization = adminOnly,
  deleteAuthorization = adminOnly,
  beforeDelete,
) => {
  app.put(`/api/${path}/:id`, authenticate, editAuthorization, async (req, res) => {
    try {
      const updated = await Model.findByIdAndUpdate(getId(req), pick(req.body, fields), {
        new: true,
        runValidators: true,
      });
      if (!updated) return notFound(res, label);
      res.json({ status: "success", message: `${label} actualizado correctamente`, data: updated });
    } catch (error) {
      const status = error?.code === 11000 ? 409 : 400;
      res.status(status).json({ status: "error", message: `No fue posible actualizar ${label.toLowerCase()}` });
    }
  });

  app.delete(`/api/${path}/:id`, authenticate, deleteAuthorization, async (req, res) => {
    try {
      const deleteError = beforeDelete ? await beforeDelete(getId(req)) : null;
      if (deleteError) return res.status(409).json({ status: "error", message: deleteError });
      const deleted = await Model.findByIdAndDelete(getId(req));
      if (!deleted) return notFound(res, label);
      res.json({ status: "success", message: `${label} eliminado correctamente` });
    } catch {
      res.status(400).json({ status: "error", message: `No fue posible eliminar ${label.toLowerCase()}` });
    }
  });
};

//conectar con MongoDB
mongoose
  .connect(MONGO_URI, {
    //useNewUrlParser: true,
    //useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch((error) => console.error("❌ Error al conectar a MongoDB:", error));

app.get("/api/status", (req, res) => {
  res.status(200).json({ status: "Servidor funcionando correctamente" });
});

app.get("/api/estados", authenticate, (req, res) => {
  res.status(200).json({ status: "success", estados: ESTADOS });
});

app.post("/api/register", adminOrFirstUser, async (req, res) => {
  try {
    const { username, nomina, email, password, name, last_name, rolId, area } = req.body;
    if (!username || !nomina || !email || !password || !name || !last_name || !rolId || !area) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ status: "error", message: "El usuario ya existe" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      nomina,
      email,
      password: hashedPassword,
      name,
      last_name,
      rolId,
      area,
    });
    console.log("Usuario registrado:", newUser);
    res
      .status(201)
      .json({ status: "success", message: "Usuario registrado exitosamente" });
  } catch (error) {
    console.error("Error al registrar al usuario:", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar al usuario" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    const user = await User.findOne({ email })
      .populate("rolId", "name active")
      .populate("area", "name active");
    if (!user) {
      return res
        .status(400)
        .json({ status: "error", message: "Usuario no encontrado" });
    }
    if (user.active === false) {
      return res.status(403).json({ status: "error", message: "La cuenta se encuentra inactiva" });
    }
    if (!user.rolId || user.rolId.active === false) {
      return res.status(403).json({ status: "error", message: "El rol de la cuenta no está disponible" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(400)
        .json({ status: "error", message: "Contraseña incorrecta" });
    }
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 3600000,
    }); // 1 hora en milisegundos
    const safeUser = user.toObject();
    delete safeUser.password;
    return res
      .status(200)
      .json({
        status: "success",
        message: "Inicio de sesión exitoso",
        user: safeUser,
      });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al iniciar sesión" });
  }
});

app.get("/api/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId)
      .select("-password")
      .populate("rolId", "name active")
      .populate("area", "name active");
    if (!user) {
      return res
        .status(404)
        .json({ status: "error", message: "Usuario no encontrado" });
    }
    res.status(200).json({ status: "success", user: user });
  } catch (error) {
    console.error("Error al obtener los datos del usuario:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos del usuario",
    });
  }
});

app.put("/api/profile", authenticate, async (req, res) => {
  try {
    const fields = ["username", "nomina", "email", "name", "last_name", "area"];
    const update = pick(req.body, fields);
    if (req.body.password) update.password = await bcrypt.hash(req.body.password, 10);

    const user = await User.findByIdAndUpdate(req.userId, update, {
      new: true,
      runValidators: true,
    })
      .select("-password")
      .populate("rolId", "name active")
      .populate("area", "name active");

    if (!user) return notFound(res, "Usuario");
    res.json({ status: "success", message: "Perfil actualizado correctamente", user });
  } catch (error) {
    const status = error?.code === 11000 ? 409 : 400;
    const message = error?.code === 11000
      ? "El usuario, correo o número de nómina ya está registrado"
      : "No fue posible actualizar el perfil";
    res.status(status).json({ status: "error", message });
  }
});

app.get("/api/users", authenticate, async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 100);
    const search = String(req.query.search || "").trim();
    const role = String(req.query.role || "").trim();
    const filter = {};
    if (search) {
      filter.$or = [
        { username: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { name: { $regex: search, $options: "i" } },
        { last_name: { $regex: search, $options: "i" } },
      ];
    }
    if (role) {
      const escapedRole = role.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const rolePattern = /^tecnico$/i.test(role) ? /^t[eé]cnico$/i : new RegExp(`^${escapedRole}$`, "i");
      const roleDocument = await Role.findOne({ name: rolePattern }).select("_id").lean();
      if (!roleDocument) {
        return res.status(200).json({ status: "success", users: [], total: 0 });
      }
      filter.rolId = roleDocument._id;
    }
    const [users, total] = await Promise.all([
      User.find(filter).select("-password").populate("rolId", "name").populate("area", "name")
        .skip((page - 1) * limit).limit(limit).lean(),
      User.countDocuments(filter),
    ]);
    res.status(200).json({ status: "success", users, total });
  } catch (error) {
    console.error("Error al obtener usuarios:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener usuarios",
    });
  }
});

app.get("/api/getAreas", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try {
    const areas = await Area.find({});
    if (!areas) {
      return res
        .status(404)
        .json({ status: "error", message: "Áreas no encontrado" });
    }
    res.status(200).json({ status: "success", areas: areas });
  } catch (error) {
    console.error("Error al obtener los datos del área:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos del área",
    });
  }
});

app.post("/api/createArea", authenticate, adminOnly, async (req, res) => {
  console.log("Datos recibidos para alta de Área: ", req.body);
  try {
    const { name, description } = req.body;
    if (!name || !description) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    const existingArea = await Area.findOne({ name });
    if (existingArea) {
      return res
        .status(400)
        .json({ status: "error", message: "El área ya existe" });
    }
    const newArea = await Area.create({ name, description });
    console.log("Área registrada: ", newArea);
    res
      .status(201)
      .json({ status: "success", message: "Área registrada exitosamente" });
  } catch (error) {
    console.error("Error al registrar el área: ", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar el área" });
  }
});

app.get("/api/getCategories", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try { 
    const category = await Category.find({});
    if (!category) {
      return res
        .status(404)
        .json({ status: "error", message: "Categorías no encontrado" });
    }
    res.status(200).json({ status: "success", category: category });
  } catch (error) {
    console.error("Error al obtener los datos del Categorías:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos del Categorías",
    });
  }
});

app.post("/api/createCategory", authenticate, adminOnly, async (req, res) => {
  console.log("Datos para crear la categoría: ", req.body);
  try {
    const { name, description } = req.body;
    if (!name || !description) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    const existingCategory = await Category.findOne({ name });
    if (existingCategory) {
      return res
        .status(400)
        .json({ status: "error", message: "La categoría ya existe" });
    }
    const newCategory = await Category.create({ name, description });
    console.log("Catrgoría registrada: ", newCategory);
    res.status(201).json({
      status: "success",
      message: "Categoría registrada exitosamente",
    });
  } catch (error) {
    console.error("Error al registrar la categoría: ", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar la categoría" });
  }
});

app.get("/api/getRoles", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try {
    const roles = await Role.find({}, { id: 1, name: 1, description: 1, active: 1 })
      .sort({ name: 1 })
      .lean();

    res.status(200).json({ status: "success", roles: roles });
  } catch (error) {
    console.error("Error al obtener los roles para registro:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los roles",
    });
  }
});

app.post("/api/createRole", authenticate, adminOnly, async (req, res) => {
  console.log("Datos para crear el role: ", req.body);
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try {
    const { name, description } = req.body;
    if (!name || !description) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    const existingRole = await Role.findOne({ name });
    if (existingRole) {
      return res
        .status(400)
        .json({ status: "error", message: "El rol ya existe" });
    }
    const newRole = await Role.create({ name, description });
    console.log("Role registrado: ", newRole);
    res
      .status(201)
      .json({ status: "success", message: "Rol registrado exitosamente" });
  } catch (error) {
    console.error("Error al registrar el rol: ", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar el rol" });
  }
});

app.get("/api/getRolesForUser", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try {
    const roles = await Role.find({}, { id: 1, name: 1, description: 1, active: 1 })
      .sort({ name: 1 })
      .lean();

    res.status(200).json({ status: "success", roles: roles });
  } catch (error) {
    console.error("Error al obtener los roles para registro:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los roles",
    });
  }
});

app.get("/api/getItems", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try { 
    const items = await Inventario.find({}).populate("assigned_to", "username name");
    if (!items) {
      return res
        .status(404)
        .json({ status: "error", message: "Dispositivos no encontrado" });
    }
    res.status(200).json({ status: "success", items });
  } catch (error) {
    console.error("Error al obtener los datos del Dispositivos:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos del Dispositivos",
    });
  }
});

app.post("/api/createItem", authenticate, adminOnly, async (req, res) => {
  console.log("Datos para crear el item: ", req.body);
  try {
    const { type, brand, model, serial_number, status, assigned_to, asigned_to } = req.body;
    const assignedTo = assigned_to || asigned_to;
    if (!type || !brand || !serial_number || !model) {
      return res.status(400).json({
        status: "error",
        message: "Los campos son obligatorios",
      });
    }
    const existingItem = await Inventario.findOne({ serial_number });
    if (existingItem) {
      return res
        .status(400)
        .json({ status: "error", message: "El item ya existe" });
    }
    const newItem = await Inventario.create({
      type,
      brand,
      model,
      serial_number,
      status,
      assigned_to: assignedTo || null,
    });
    console.log("Item registrado: ", newItem);
    res
      .status(201)
      .json({ status: "success", message: "Dispositivo registrado exitosamente" });
  } catch (error) {
    console.error("Error al registrar el dispoditivo: ", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar el dispositivo" });
  }
});

app.get("/api/getTickets", authenticate, async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 100);
    const search = String(req.query.search || "").trim();
    const filter = req.query.assignedToMe === "true" ? { tecnico_id: req.userId } : {};
    if (search) {
      filter.$or = [
        { folio: { $regex: search, $options: "i" } },
        { titulo: { $regex: search, $options: "i" } },
        { descripcion: { $regex: search, $options: "i" } },
      ];
    }
    const [tickets, total] = await Promise.all([
      Ticket.find(filter)
        .populate("solicitante_id", "username name last_name")
        .populate("tecnico_id", "username name last_name")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Ticket.countDocuments(filter),
    ]);
    res.status(200).json({ status: "success", tickets, total });
  } catch (error) {
    console.error("Error al obtener los datos de Tickets:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos de Tickets",
    });
  }
});

app.post("/api/createTicket", authenticate, async (req, res) => {
  try {
    const { titulo, descripcion, prioridad, solucion } = req.body;
    if (!titulo || !descripcion || !prioridad) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    await Ticket.create({ titulo, descripcion, prioridad, solucion, solicitante_id: req.userId });
    res.status(201).json({ status: "success", message: "Ticket registrado exitosamente" });
  } catch (error) {
    console.error("Error al registrar el ticket:", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar el ticket" });
  }
});

app.get("/api/getSolicitudes", authenticate, async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 100);
    const search = String(req.query.search || "").trim();
    const filter = req.query.assignedToMe === "true" ? { tecnico_id: req.userId } : {};
    if (search) {
      filter.$or = [
        { folio: { $regex: search, $options: "i" } },
        { tipo: { $regex: search, $options: "i" } },
        { descripcion: { $regex: search, $options: "i" } },
      ];
    }
    const [solicitudes, total] = await Promise.all([
      Solicitud.find(filter)
        .populate("solicitante_id", "username name last_name")
        .populate("tecnico_id", "username name last_name")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Solicitud.countDocuments(filter),
    ]);
    res.status(200).json({ status: "success", solicitudes, total });
  } catch (error) {
    console.error("Error al obtener los datos del Solicitudes:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos del Solicitudes",
    });
  }
});

app.post("/api/createSolicitud", authenticate, async (req, res) => {
  try {
    const { tipo, descripcion, comentarios, area, prioridad } = req.body;
    if (!tipo || !descripcion || !area || !prioridad) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    await Solicitud.create({ tipo, descripcion, comentarios, area, prioridad, solicitante_id: req.userId });
    res.status(201).json({ status: "success", message: "Solicitud registrada exitosamente" });
  } catch (error) {
    console.error("Error al registrar la solicitud:", error);
    res
      .status(500)
      .json({ status: "error", message: "Error al registrar la solicitud" });
  }
});

app.put("/api/users/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const fields = ["username", "nomina", "email", "name", "last_name", "rolId", "area", "active"];
    const update = pick(req.body, fields);
    if (req.body.password) update.password = await bcrypt.hash(req.body.password, 10);
    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true })
      .select("-password");
    if (!user) return notFound(res, "Usuario");
    res.json({ status: "success", message: "Usuario actualizado correctamente", user });
  } catch (error) {
    const status = error?.code === 11000 ? 409 : 400;
    res.status(status).json({ status: "error", message: "No fue posible actualizar el usuario" });
  }
});

app.delete("/api/users/:id", authenticate, adminOnly, async (req, res) => {
  if (String(req.userId) === req.params.id) {
    return res.status(400).json({ status: "error", message: "No puedes eliminar tu propia cuenta" });
  }
  try {
    const references = await Promise.all([
      Inventario.exists({ assigned_to: req.params.id }),
      Asignacion.exists({ $or: [{ user_id: req.params.id }, { assigned_by: req.params.id }] }),
      Solicitud.exists({ $or: [{ solicitante_id: req.params.id }, { supervisor_id: req.params.id }, { tecnico_id: req.params.id }] }),
      Ticket.exists({ $or: [{ solicitante_id: req.params.id }, { supervisor_id: req.params.id }, { tecnico_id: req.params.id }] }),
    ]);
    const hasReferences = references.some(Boolean);
    if (hasReferences) {
      return res.status(409).json({
        status: "error",
        message: "El usuario tiene registros relacionados; desactívalo en lugar de eliminarlo",
      });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return notFound(res, "Usuario");
    res.json({ status: "success", message: "Usuario eliminado correctamente" });
  } catch {
    res.status(400).json({ status: "error", message: "No fue posible eliminar el usuario" });
  }
});

registerCrudRoutes(
  "areas",
  Area,
  ["name", "description", "active"],
  "Área",
  adminOnly,
  adminOnly,
  async (id) =>
    (await User.exists({ area: id })) || (await Solicitud.exists({ area: id }))
      ? "El área tiene registros relacionados; desactívala en lugar de eliminarla"
      : null,
);
registerCrudRoutes("categories", Category, ["name", "description", "active"], "Categoría");
registerCrudRoutes(
  "roles",
  Role,
  ["name", "description", "active", "permissions"],
  "Rol",
  adminOnly,
  adminOnly,
  async (id) =>
    (await User.exists({ rolId: id }))
      ? "El rol está asignado a usuarios; desactívalo en lugar de eliminarlo"
      : null,
);
registerCrudRoutes(
  "items",
  Inventario,
  ["type", "brand", "model", "serial_number", "status", "assigned_to"],
  "Equipo",
  adminOnly,
  adminOnly,
  async (id) =>
    (await Asignacion.exists({ inventory_id: id }))
      ? "El equipo tiene historial de asignaciones; cámbialo a estado Baja en lugar de eliminarlo"
      : null,
);
registerCrudRoutes(
  "solicitudes",
  Solicitud,
  ["tipo", "descripcion", "area", "prioridad", "estado", "comentarios", "supervisor_id", "tecnico_id", "fecha_aprobacion", "fecha_cierre"],
  "Solicitud",
  authorizeWorkItemUpdate,
  adminOnly,
);
registerCrudRoutes(
  "tickets",
  Ticket,
  ["titulo", "descripcion", "prioridad", "estado", "comentarios", "solucion", "supervisor_id", "tecnico_id", "fecha_cierre"],
  "Ticket",
  authorizeWorkItemUpdate,
  adminOnly,
);

app.get("/api/assignments", authenticate, adminOnly, async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 100);
    const filter = {};
    if (req.query.inventory_id) filter.inventory_id = req.query.inventory_id;
    if (req.query.user_id) filter.user_id = req.query.user_id;
    if (req.query.active === "true") filter.active = true;
    if (req.query.active === "false") filter.active = false;

    const [assignments, total] = await Promise.all([
      Asignacion.find(filter)
        .populate("inventory_id", "id type brand model serial_number status")
        .populate("user_id", "username name last_name nomina")
        .populate("assigned_by", "username name last_name")
        .sort({ assigned_at: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Asignacion.countDocuments(filter),
    ]);
    res.json({ status: "success", assignments, total });
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible obtener las asignaciones" });
  }
});

app.post("/api/assignments", authenticate, adminOnly, async (req, res) => {
  const { inventory_id, user_id, notes } = req.body;
  if (!inventory_id || !user_id) {
    return res.status(400).json({ status: "error", message: "El equipo y el usuario son obligatorios" });
  }

  try {
    const [item, user, currentAssignment] = await Promise.all([
      Inventario.findById(inventory_id),
      User.findById(user_id),
      Asignacion.findOne({ inventory_id, active: true }),
    ]);
    if (!item) return notFound(res, "Equipo");
    if (!user) return notFound(res, "Usuario");
    if (String(item.status || "").toLowerCase() === "baja") {
      return res.status(409).json({ status: "error", message: "Un equipo dado de baja no puede asignarse" });
    }
    if (currentAssignment) {
      return res.status(409).json({ status: "error", message: "El equipo ya tiene una asignación activa" });
    }

    const assignment = await Asignacion.create({
      inventory_id,
      user_id,
      assigned_by: req.userId,
      notes,
    });
    try {
      await Inventario.findByIdAndUpdate(inventory_id, { assigned_to: user_id, status: "Asignado" });
    } catch (error) {
      await Asignacion.findByIdAndDelete(assignment._id);
      throw error;
    }
    res.status(201).json({ status: "success", message: "Equipo asignado correctamente", assignment });
  } catch (error) {
    const status = error?.code === 11000 ? 409 : 400;
    res.status(status).json({ status: "error", message: "No fue posible asignar el equipo" });
  }
});

app.put("/api/assignments/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const assignment = await Asignacion.findByIdAndUpdate(
      req.params.id,
      pick(req.body, ["notes", "return_notes"]),
      { new: true, runValidators: true },
    );
    if (!assignment) return notFound(res, "Asignación");
    res.json({
      status: "success",
      message: "Asignación actualizada correctamente",
      assignment,
    });
  } catch (error) {
    res.status(400).json({
      status: "error",
      message: "No fue posible actualizar la asignación",
    });
  }
});

app.delete("/api/assignments/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const assignment = await Asignacion.findById(req.params.id);
    if (!assignment) return notFound(res, "Asignación");

    if (assignment.active) {
      await Inventario.updateOne(
        { _id: assignment.inventory_id, assigned_to: assignment.user_id },
        { $set: { assigned_to: null, status: "Disponible" } },
      );
    }

    await assignment.deleteOne();
    res.json({ status: "success", message: "Asignación eliminada correctamente" });
  } catch (error) {
    res.status(400).json({
      status: "error",
      message: "No fue posible eliminar la asignación",
    });
  }
});

app.patch("/api/assignments/:id/return", authenticate, adminOnly, async (req, res) => {
  try {
    const assignment = await Asignacion.findOne({ _id: req.params.id, active: true });
    if (!assignment) return notFound(res, "Asignación activa");

    assignment.active = false;
    assignment.returned_at = new Date();
    assignment.return_notes = req.body.return_notes || "";
    await assignment.save();
    await Inventario.findByIdAndUpdate(assignment.inventory_id, {
      $set: { assigned_to: null, status: "Disponible" },
    });

    res.json({ status: "success", message: "Devolución registrada correctamente", assignment });
  } catch {
    res.status(400).json({ status: "error", message: "No fue posible registrar la devolución" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie('token', { path: '/', httpOnly: true, secure: false, sameSite: 'lax' });
    res
      .status(200)
      .json({ status: "success", message: "Cierre de sesión exitoso" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
