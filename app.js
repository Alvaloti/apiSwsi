import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import User from "./model/User.js";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import multer from "multer";
import path from "node:path";
import Area from "./model/Area.js";
import Category from "./model/Categoria.js";
import Role from "./model/Role.js";
import Inventario from "./model/Inventario.js";
import Solicitud from "./model/Solicitud.js";
import Ticket from "./model/Ticket.js";
import Asignacion from "./model/Asignacion.js";
import Adjunto from "./model/Adjunto.js";
import Notificacion from "./model/Notificacion.js";
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

const allowedOrigins = (
  process.env.FRONTEND_ORIGINS ||
  "http://localhost:4200"
)
  .split(",")
  .map(origin => origin.trim());

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origen no permitido por CORS"));
    },
    credentials: true,
  }),
);

app.use(cookieParser());

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  path: "/",
};

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI || !JWT_SECRET) {
  console.error("Faltan las variables de entorno MONGO_URI o JWT_SECRET");
  process.exit(1);
}

const allowedAttachmentTypes = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
]);
const uploadAttachment = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => {
    if (!allowedAttachmentTypes.has(file.mimetype)) {
      const error = new Error("Sólo se permiten archivos PDF, JPEG, PNG, GIF o WebP");
      error.code = "INVALID_FILE_TYPE";
      return callback(error);
    }
    callback(null, true);
  },
});
const receiveAttachment = (req, res, next) => {
  uploadAttachment.single("file")(req, res, (error) => {
    if (!error) return next();
    const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "El archivo no puede superar 10 MB"
      : error.message || "No fue posible procesar el archivo";
    return res.status(status).json({ status: "error", message });
  });
};

const authenticate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ status: "error", message: "No autorizado" });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).userId;
    next();
  } catch {
    res.clearCookie("token", cookieOptions);
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
const adminOrSupervisor = authorizeRoles("admin", "administrador", "supervisor");
const supportStaff = authorizeRoles("admin", "administrador", "supervisor", "tecnico", "técnico");
const getWorkItemVisibility = async (userId) => {
  const user = await User.findById(userId).populate("rolId", "name active").lean();
  if (!user || user.active === false || !user.rolId || user.rolId.active === false) {
    const error = new Error("La cuenta o su rol no están disponibles");
    error.status = 403;
    throw error;
  }

  const role = String(user.rolId.name || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim();

  if (["admin", "administrador", "supervisor"].includes(role)) return {};
  if (role === "tecnico") return { tecnico_id: userId };
  return { solicitante_id: userId };
};
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

const notifyWorkItemChanges = async (path, previous, updated, actorId) => {
  if (!previous || !updated || !["solicitudes", "tickets"].includes(path)) return;

  const entityType = path === "solicitudes" ? "solicitud" : "ticket";
  const entityLabel = entityType === "solicitud" ? "Solicitud" : "Ticket";
  const folio = updated.folio || updated._id;
  const notifications = [];
  const previousTechnician = String(previous.tecnico_id || "");
  const currentTechnician = String(updated.tecnico_id || "");

  if (currentTechnician && currentTechnician !== previousTechnician && currentTechnician !== String(actorId)) {
    notifications.push({
      recipient: updated.tecnico_id,
      type: "assignment",
      title: `${entityLabel} asignado`,
      message: `Se te asignó ${entityLabel.toLowerCase()} ${folio}.`,
      entity_type: entityType,
      entity_id: updated._id,
    });
  }

  if (
    updated.estado !== previous.estado &&
    updated.solicitante_id &&
    String(updated.solicitante_id) !== String(actorId)
  ) {
    notifications.push({
      recipient: updated.solicitante_id,
      type: "status",
      title: `Estado de ${entityLabel.toLowerCase()} actualizado`,
      message: `${entityLabel} ${folio} cambió de “${previous.estado}” a “${updated.estado}”.`,
      entity_type: entityType,
      entity_id: updated._id,
    });
  }

  if (notifications.length) await Notificacion.insertMany(notifications);
};

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
      const previous = ["solicitudes", "tickets"].includes(path)
        ? await Model.findById(getId(req)).lean()
        : null;
      const updated = await Model.findByIdAndUpdate(getId(req), pick(req.body, fields), {
        new: true,
        runValidators: true,
      });
      if (!updated) return notFound(res, label);
      try {
        await notifyWorkItemChanges(path, previous, updated, req.userId);
      } catch (notificationError) {
        console.error("No fue posible crear la notificación:", notificationError);
      }
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
      ...cookieOptions,
      maxAge: 60 * 60 * 1000,
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
    const filter = await getWorkItemVisibility(req.userId);
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
    res.status(error.status || 500).json({
      status: "error",
      message: error.status ? error.message : "Error al obtener los datos de Tickets",
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
    const ticket = await Ticket.create({
      titulo,
      descripcion,
      prioridad,
      solucion,
      solicitante_id: req.userId,
    });
    res.status(201).json({
      status: "success",
      message: "Ticket registrado exitosamente",
      ticket,
    });
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
    const filter = await getWorkItemVisibility(req.userId);
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
    res.status(error.status || 500).json({
      status: "error",
      message: error.status ? error.message : "Error al obtener los datos del Solicitudes",
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
    if (!mongoose.isValidObjectId(area)) {
      return res.status(400).json({ status: "error", message: "El área seleccionada no es válida" });
    }
    const selectedArea = await Area.exists({ _id: area, active: { $ne: false } });
    if (!selectedArea) {
      return res.status(400).json({ status: "error", message: "El área seleccionada no está disponible" });
    }
    const solicitud = await Solicitud.create({
      tipo,
      descripcion,
      comentarios,
      area,
      prioridad,
      solicitante_id: req.userId,
    });
    res.status(201).json({
      status: "success",
      message: "Solicitud registrada exitosamente",
      solicitud,
    });
  } catch (error) {
    console.error("Error al registrar la solicitud:", error);
    if (error?.code === 11000) {
      return res.status(409).json({
        status: "error",
        message: "No fue posible generar un folio único; intenta nuevamente",
      });
    }
    if (error?.name === "ValidationError" || error?.name === "CastError") {
      return res.status(400).json({
        status: "error",
        message: "Los datos de la solicitud no son válidos",
      });
    }
    res.status(500).json({ status: "error", message: "Error interno al registrar la solicitud" });
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

const attachmentResponse = (attachment) => ({
  _id: attachment._id,
  solicitud_id: attachment.solicitud_id,
  ticket_id: attachment.ticket_id,
  name: attachment.name,
  mime_type: attachment.mime_type,
  ext: attachment.ext,
  size: attachment.size,
  uploaded_by: attachment.uploaded_by,
  createdAt: attachment.createdAt,
  updatedAt: attachment.updatedAt,
  url: `/api/attachments/${attachment._id}/file`,
});

app.post(
  "/api/attachments",
  authenticate,
  receiveAttachment,
  async (req, res) => {
    try {
      const { solicitud_id, ticket_id } = req.body;
      if (!req.file) {
        return res.status(400).json({ status: "error", message: "El archivo es obligatorio" });
      }
      if (Boolean(solicitud_id) === Boolean(ticket_id)) {
        return res.status(400).json({
          status: "error",
          message: "Indica exclusivamente solicitud_id o ticket_id",
        });
      }

      const parentId = solicitud_id || ticket_id;
      if (!mongoose.isValidObjectId(parentId)) {
        return res.status(400).json({ status: "error", message: "Identificador inválido" });
      }
      const parent = solicitud_id
        ? await Solicitud.exists({ _id: solicitud_id })
        : await Ticket.exists({ _id: ticket_id });
      if (!parent) {
        return notFound(res, solicitud_id ? "Solicitud" : "Ticket");
      }

      const name = path.basename(req.file.originalname);
      const ext = path.extname(name).slice(1).toLowerCase() ||
        (req.file.mimetype === "application/pdf" ? "pdf" : req.file.mimetype.split("/")[1]);
      const attachment = await Adjunto.create({
        solicitud_id: solicitud_id || null,
        ticket_id: ticket_id || null,
        name,
        mime_type: req.file.mimetype,
        ext,
        size: req.file.size,
        data: req.file.buffer,
        uploaded_by: req.userId,
      });

      res.status(201).json({
        status: "success",
        message: "Archivo adjunto guardado correctamente",
        attachment: attachmentResponse(attachment),
      });
    } catch (error) {
      console.error("Error al guardar el archivo adjunto:", error);
      res.status(400).json({ status: "error", message: "No fue posible guardar el archivo adjunto" });
    }
  },
);

app.get("/api/attachments", authenticate, async (req, res) => {
  try {
    const { solicitud_id, ticket_id } = req.query;
    if (Boolean(solicitud_id) === Boolean(ticket_id)) {
      return res.status(400).json({
        status: "error",
        message: "Indica exclusivamente solicitud_id o ticket_id",
      });
    }
    const filter = solicitud_id ? { solicitud_id } : { ticket_id };
    const attachments = await Adjunto.find(filter)
      .populate("uploaded_by", "id username name last_name")
      .sort({ createdAt: -1 })
      .lean();
    res.json({
      status: "success",
      attachments: attachments.map(attachmentResponse),
    });
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible obtener los archivos adjuntos" });
  }
});

app.get("/api/attachments/:id/file", authenticate, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return notFound(res, "Archivo adjunto");
    const attachment = await Adjunto.findById(req.params.id).select("+data");
    if (!attachment) return notFound(res, "Archivo adjunto");

    res.setHeader("Content-Type", attachment.mime_type);
    res.setHeader("Content-Length", attachment.size);
    res.setHeader("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(attachment.name)}`);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(attachment.data);
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible obtener el archivo adjunto" });
  }
});

app.delete("/api/attachments/:id", authenticate, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return notFound(res, "Archivo adjunto");
    const attachment = await Adjunto.findByIdAndDelete(req.params.id);
    if (!attachment) return notFound(res, "Archivo adjunto");
    res.json({ status: "success", message: "Archivo adjunto eliminado correctamente" });
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible eliminar el archivo adjunto" });
  }
});

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

app.get("/api/reports", authenticate, adminOrSupervisor, async (req, res) => {
  try {
    const type = ["solicitudes", "tickets", "tecnicos"].includes(req.query.type)
      ? req.query.type
      : "solicitudes";
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 100);
    const search = String(req.query.search || "").trim();
    const dateFilter = {};

    if (req.query.from) {
      const from = new Date(`${req.query.from}T00:00:00.000-06:00`);
      if (Number.isNaN(from.getTime())) {
        return res.status(400).json({ status: "error", message: "Fecha inicial inválida" });
      }
      dateFilter.$gte = from;
    }
    if (req.query.to) {
      const to = new Date(`${req.query.to}T23:59:59.999-06:00`);
      if (Number.isNaN(to.getTime())) {
        return res.status(400).json({ status: "error", message: "Fecha final inválida" });
      }
      dateFilter.$lte = to;
    }
    if (dateFilter.$gte && dateFilter.$lte && dateFilter.$gte > dateFilter.$lte) {
      return res.status(400).json({ status: "error", message: "La fecha inicial no puede ser posterior a la final" });
    }

    const baseMatch = Object.keys(dateFilter).length ? { createdAt: dateFilter } : {};
    const [solicitudSummary, ticketSummary] = await Promise.all([
      Solicitud.aggregate([
        { $match: baseMatch },
        { $group: { _id: "$estado", total: { $sum: 1 }, unassigned: { $sum: { $cond: [{ $eq: [{ $ifNull: ["$tecnico_id", null] }, null] }, 1, 0] } } } },
      ]),
      Ticket.aggregate([
        { $match: baseMatch },
        { $group: { _id: "$estado", total: { $sum: 1 }, unassigned: { $sum: { $cond: [{ $eq: [{ $ifNull: ["$tecnico_id", null] }, null] }, 1, 0] } } } },
      ]),
    ]);
    const sumTotals = (groups) => groups.reduce(
      (result, group) => ({ total: result.total + group.total, unassigned: result.unassigned + group.unassigned }),
      { total: 0, unassigned: 0 },
    );
    const solicitudTotals = sumTotals(solicitudSummary);
    const ticketTotals = sumTotals(ticketSummary);
    const summary = {
      solicitudes: solicitudTotals.total,
      tickets: ticketTotals.total,
      sin_asignar: solicitudTotals.unassigned + ticketTotals.unassigned,
      cerrados: [...solicitudSummary, ...ticketSummary]
        .filter((item) => ["resuelto", "cerrado"].includes(item._id))
        .reduce((total, item) => total + item.total, 0),
      estados_solicitudes: solicitudSummary.map((item) => ({ estado: item._id, total: item.total })),
      estados_tickets: ticketSummary.map((item) => ({ estado: item._id, total: item.total })),
    };

    if (type === "solicitudes" || type === "tickets") {
      const Model = type === "solicitudes" ? Solicitud : Ticket;
      const textFields = type === "solicitudes" ? ["folio", "tipo", "descripcion"] : ["folio", "titulo", "descripcion"];
      const match = { ...baseMatch };
      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        match.$or = textFields.map((field) => ({ [field]: { $regex: escaped, $options: "i" } }));
      }
      const [rows, total] = await Promise.all([
        Model.find(match)
          .populate("solicitante_id", "username name last_name")
          .populate("tecnico_id", "username name last_name")
          .sort({ createdAt: -1 })
          .skip((page - 1) * limit)
          .limit(limit)
          .lean(),
        Model.countDocuments(match),
      ]);
      return res.json({ status: "success", type, summary, rows, total });
    }

    const technicianRoles = await Role.find({ name: /^t[eé]cnico$/i }).select("_id").lean();
    const technicianMatch = { rolId: { $in: technicianRoles.map((role) => role._id) } };
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      technicianMatch.$or = ["username", "name", "last_name", "email"].map((field) => ({
        [field]: { $regex: escaped, $options: "i" },
      }));
    }
    const [technicians, total, solicitudLoads, ticketLoads] = await Promise.all([
      User.find(technicianMatch)
        .select("username name last_name email active area")
        .populate("area", "name")
        .sort({ name: 1, last_name: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      User.countDocuments(technicianMatch),
      Solicitud.aggregate([{ $match: { ...baseMatch, tecnico_id: { $ne: null } } }, { $group: { _id: "$tecnico_id", total: { $sum: 1 }, cerrados: { $sum: { $cond: [{ $in: ["$estado", ["resuelto", "cerrado"]] }, 1, 0] } } } }]),
      Ticket.aggregate([{ $match: { ...baseMatch, tecnico_id: { $ne: null } } }, { $group: { _id: "$tecnico_id", total: { $sum: 1 }, cerrados: { $sum: { $cond: [{ $in: ["$estado", ["resuelto", "cerrado"]] }, 1, 0] } } } }]),
    ]);
    const loadMap = new Map();
    for (const group of [...solicitudLoads, ...ticketLoads]) {
      const id = String(group._id);
      const current = loadMap.get(id) || { asignados: 0, cerrados: 0 };
      current.asignados += group.total;
      current.cerrados += group.cerrados;
      loadMap.set(id, current);
    }
    const rows = technicians.map((technician) => ({
      ...technician,
      ...(loadMap.get(String(technician._id)) || { asignados: 0, cerrados: 0 }),
    }));
    return res.json({ status: "success", type, summary, rows, total });
  } catch (error) {
    console.error("Error al generar el reporte:", error);
    res.status(500).json({ status: "error", message: "No fue posible generar el reporte" });
  }
});

app.get("/api/notifications", authenticate, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 50);
    const [notifications, unreadCount] = await Promise.all([
      Notificacion.find({ recipient: req.userId })
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean(),
      Notificacion.countDocuments({ recipient: req.userId, read_at: null }),
    ]);
    res.json({ status: "success", notifications, unreadCount });
  } catch (error) {
    res.status(500).json({ status: "error", message: "No fue posible obtener las notificaciones" });
  }
});

app.patch("/api/notifications/read-all", authenticate, async (req, res) => {
  try {
    await Notificacion.updateMany(
      { recipient: req.userId, read_at: null },
      { $set: { read_at: new Date() } },
    );
    res.json({ status: "success", message: "Notificaciones marcadas como leídas" });
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible actualizar las notificaciones" });
  }
});

app.patch("/api/notifications/:id/read", authenticate, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return notFound(res, "Notificación");
    const notification = await Notificacion.findOneAndUpdate(
      { _id: req.params.id, recipient: req.userId },
      { $set: { read_at: new Date() } },
      { new: true },
    );
    if (!notification) return notFound(res, "Notificación");
    res.json({ status: "success", notification });
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible actualizar la notificación" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token", cookieOptions);
    res
      .status(200)
      .json({ status: "success", message: "Cierre de sesión exitoso" });
});

app.set("trust proxy", 1);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
