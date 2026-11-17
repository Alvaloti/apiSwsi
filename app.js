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
import crypto from "node:crypto";
import nodemailer from "nodemailer";
import Area from "./model/Area.js";
import Category from "./model/Categoria.js";
import Role from "./model/Role.js";
import Inventario from "./model/Inventario.js";
import Solicitud from "./model/Solicitud.js";
import Ticket from "./model/Ticket.js";
import Asignacion from "./model/Asignacion.js";
import Adjunto from "./model/Adjunto.js";
import Notificacion from "./model/Notificacion.js";
import Catalogo from "./model/Catalogo.js";
import Mantenimiento from "./model/Mantenimiento.js";
import EquipoEvento from "./model/EquipoEvento.js";
import Auditoria from "./model/Auditoria.js";
import SlaPolicy from "./model/SlaPolicy.js";
import NotificationPreference from "./model/NotificationPreference.js";
import NotificationSetting from "./model/NotificationSetting.js";
import SystemSetting from "./model/SystemSetting.js";
const noCache = (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
};

dotenv.config();

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI || !JWT_SECRET) {
  console.error("Faltan las variables de entorno MONGO_URI o JWT_SECRET");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1);
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

const sensitiveAuditFields = new Set(["password", "token", "authorization", "data", "file"]);
const sanitizeAuditValue = (value, key = "", depth = 0) => {
  if (sensitiveAuditFields.has(String(key).toLowerCase())) return "[REDACTADO]";
  if (value === null || value === undefined) return value;
  if (depth > 2) return "[DATOS OMITIDOS]";
  if (typeof value === "string") return value.length > 500 ? `${value.slice(0, 500)}…` : value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitizeAuditValue(item, key, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 30)
        .map(([childKey, childValue]) => [childKey, sanitizeAuditValue(childValue, childKey, depth + 1)]),
    );
  }
  return String(value);
};
const requestAuditContext = (req) => ({
  ip: req.ip || req.socket?.remoteAddress || "",
  user_agent: String(req.get("user-agent") || "").slice(0, 1000),
});
const requestSessionEmail = (req) => {
  try {
    return normalizeEmail(req.cookies?.token ? jwt.verify(req.cookies.token, JWT_SECRET).email : "");
  } catch {
    return "";
  }
};
const recordAudit = (entry) => {
  Auditoria.create({ occurred_at: new Date(), ...entry }).catch((error) => {
    console.error("No fue posible registrar la auditoría:", error);
  });
};
const auditAccess = (req, entry) => recordAudit({
  category: "acceso",
  method: req.method,
  path: req.originalUrl.split("?")[0],
  resource: "sesion",
  ...requestAuditContext(req),
  ...entry,
});

app.use((req, res, next) => {
  const pathWithoutQuery = req.originalUrl.split("?")[0];
  const excludedPaths = new Set(["/api/login", "/api/logout", "/api/forgot-password", "/api/reset-password"]);
  const shouldAudit = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && !excludedPaths.has(pathWithoutQuery);
  if (shouldAudit) {
    res.on("finish", () => {
      const pathParts = pathWithoutQuery.split("/").filter(Boolean);
      const resourceId = pathParts.find((part) => mongoose.isValidObjectId(part)) || "";
      const actions = { POST: "crear", PUT: "actualizar", PATCH: "accion", DELETE: "eliminar" };
      recordAudit({
        category: "operacion",
        action: actions[req.method] || req.method.toLowerCase(),
        user_id: req.userId || null,
        user_email: requestSessionEmail(req),
        method: req.method,
        path: pathWithoutQuery,
        resource: pathParts[1] || "api",
        resource_id: resourceId,
        success: res.statusCode < 400,
        status_code: res.statusCode,
        ...requestAuditContext(req),
        details: {
          body: sanitizeAuditValue(req.body || {}),
          query: sanitizeAuditValue(req.query || {}),
        },
      });
    });
  }
  next();
});

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  path: "/",
};

const USERNAME_PATTERN = /^[A-Za-z0-9]+\.[A-Za-z0-9]+$/;
const MAX_FAILED_LOGIN_ATTEMPTS = 3;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const PASSWORD_RESET_MS = 30 * 60 * 1000;
const PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
const PERMISSIONS = [
  ["system.manage", "Administración general", "Acceso completo a catálogos y configuración"],
  ["users.manage", "Gestionar usuarios", "Crear, editar y eliminar usuarios"],
  ["roles.manage", "Gestionar roles", "Crear roles y configurar sus permisos"],
  ["catalogs.manage", "Gestionar catálogos", "Administrar áreas, categorías, estados y prioridades"],
  ["inventory.manage", "Gestionar inventario", "Administrar equipos, mantenimientos y asignaciones"],
  ["reports.view", "Consultar reportes", "Visualizar y exportar reportes"],
  ["audit.view", "Consultar auditoría", "Visualizar accesos y operaciones"],
  ["sla.manage", "Configurar SLA", "Modificar políticas de nivel de servicio"],
  ["notifications.manage", "Configurar notificaciones", "Administrar las reglas globales de notificación"],
  ["settings.manage", "Parámetros generales", "Modificar la configuración general del sistema"],
  ["work.view_all", "Ver todos los casos", "Consultar todas las solicitudes y tickets"],
  ["work.view_assigned", "Ver casos asignados", "Consultar solicitudes y tickets asignados"],
  ["work.assign", "Asignar técnicos", "Asignar solicitudes y tickets"],
  ["requests.decide", "Aprobar solicitudes", "Aprobar o rechazar solicitudes"],
  ["work.update_status", "Actualizar estados", "Cambiar estados y comentarios técnicos"],
  ["tickets.solve", "Resolver tickets", "Registrar soluciones y cerrar tickets"],
  ["tickets.escalate", "Escalar tickets", "Escalar tickets para reasignación"],
  ["work.receive_assignment", "Recibir asignaciones", "Ser seleccionado como técnico"],
];
const ALL_PERMISSION_KEYS = PERMISSIONS.map(([key]) => key);
const DEFAULT_ROLE_PERMISSIONS = {
  admin: ALL_PERMISSION_KEYS,
  administrador: ALL_PERMISSION_KEYS,
  supervisor: ["reports.view", "work.view_all", "work.assign", "requests.decide"],
  tecnico: ["work.view_assigned", "work.update_status", "tickets.solve", "tickets.escalate", "work.receive_assignment"],
  solicitante: [],
  reporte: [],
};
let permissionMigrationPromise;
const ensureRolePermissions = () => {
  if (!permissionMigrationPromise) {
    permissionMigrationPromise = (async () => {
      for (const [name, permissions] of Object.entries(DEFAULT_ROLE_PERMISSIONS)) {
        await Role.updateMany(
          { name: { $regex: `^${name}$`, $options: "i" }, permissions_version: { $ne: 1 } },
          { $set: { permissions, permissions_version: 1 } },
        );
      }
      await Role.updateMany({ permissions_version: { $ne: 1 } }, { $set: { permissions_version: 1 } });
    })().catch((error) => { permissionMigrationPromise = null; throw error; });
  }
  return permissionMigrationPromise;
};
const DEFAULT_CATALOGS = [
  ...["nuevo", "abierto", "pendiente", "en espera", "resuelto", "cerrado"].map((key, order) => ({
    type: "estado", key, name: key.replace(/(^|\s)\S/g, (letter) => letter.toUpperCase()), applies_to: "ambos", order: order + 1, active: true, system: true,
  })),
  ...[
    ["muy-baja", "Muy baja"], ["baja", "Baja"], ["media", "Media"], ["alta", "Alta"], ["muy-alta", "Muy alta"],
  ].map(([key, name], order) => ({ type: "prioridad", key, name, applies_to: "ambos", order: order + 1, active: true, system: true })),
];
const catalogKey = (value) => String(value || "")
  .normalize("NFD")
  .replace(/[\u0300-\u036f]/g, "")
  .toLowerCase()
  .trim()
  .replace(/[^a-z0-9]+/g, "-")
  .replace(/^-+|-+$/g, "")
  .slice(0, 50);
const ensureDefaultCatalogs = () => Catalogo.bulkWrite(
  DEFAULT_CATALOGS.map((item) => ({
    updateOne: { filter: { type: item.type, key: item.key }, update: { $setOnInsert: item }, upsert: true },
  })),
  { ordered: false },
);
const findActiveCatalogValue = async (type, key, appliesTo) => {
  await ensureDefaultCatalogs();
  return Catalogo.exists({
    type,
    key: String(key || "").toLowerCase(),
    active: true,
    applies_to: { $in: ["ambos", appliesTo] },
  });
};
const DEFAULT_SLA_POLICIES = [
  ["muy-baja", 24, 72], ["baja", 12, 48], ["media", 8, 24], ["alta", 4, 12], ["muy-alta", 1, 4],
].map(([priority, response_hours, resolution_hours]) => ({ priority, response_hours, resolution_hours, warning_percent: 80, active: true }));
const ensureDefaultSlaPolicies = () => SlaPolicy.bulkWrite(
  DEFAULT_SLA_POLICIES.map((item) => ({
    updateOne: { filter: { priority: item.priority }, update: { $setOnInsert: item }, upsert: true },
  })),
  { ordered: false },
);
const buildSlaDates = async (priority, start = new Date()) => {
  await ensureDefaultSlaPolicies();
  const policy = await SlaPolicy.findOne({ priority: String(priority || "").toLowerCase(), active: true }).lean();
  if (!policy) return {};
  const responseMs = policy.response_hours * 60 * 60 * 1000;
  const resolutionMs = policy.resolution_hours * 60 * 60 * 1000;
  return {
    sla_response_due: new Date(start.getTime() + responseMs),
    sla_resolution_due: new Date(start.getTime() + resolutionMs),
    sla_warning_at: new Date(start.getTime() + resolutionMs * (policy.warning_percent / 100)),
  };
};
const notificationPreferenceFields = ["assignment", "status", "decision", "solution", "escalation", "closure", "sla_warning", "sla_breach"];
const getNotificationPreferences = async (userId) => NotificationPreference.findOneAndUpdate(
  { user_id: userId }, { $setOnInsert: { user_id: userId } }, { returnDocument: "after", upsert: true, setDefaultsOnInsert: true },
);
const getGlobalNotificationSettings = () => NotificationSetting.findOneAndUpdate(
  { key: "global" }, { $setOnInsert: { key: "global" } }, { returnDocument: "after", upsert: true, setDefaultsOnInsert: true },
);
let lastNotificationCleanup = 0;
const cleanExpiredNotifications = async (retentionDays) => {
  if (Date.now() - lastNotificationCleanup < 60 * 60 * 1000) return;
  lastNotificationCleanup = Date.now();
  const threshold = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  await Notificacion.deleteMany({ createdAt: { $lt: threshold } });
};
const normalizeUsername = (value) => String(value || "").trim().toLowerCase();
const isValidUsername = (value) => {
  const username = normalizeUsername(value);
  return username.length <= 50 && USERNAME_PATTERN.test(username);
};

const normalizeEmail = (value) => String(value || "").trim().toLowerCase();
const isStrongPassword = (value) => PASSWORD_PATTERN.test(String(value || ""));

const bootstrapInitialAdmin = async () => {
  if (String(process.env.BOOTSTRAP_ADMIN_ENABLED || "").toLowerCase() !== "true") return;

  const adminRoleIds = await Role.find({ permissions: "system.manage", active: { $ne: false } }).distinct("_id");
  if (adminRoleIds.length && await User.exists({ rolId: { $in: adminRoleIds }, active: { $ne: false } })) {
    console.log("Administrador inicial: ya existe una cuenta administrativa activa");
    return;
  }

  const config = {
    username: String(process.env.BOOTSTRAP_ADMIN_USERNAME || "").trim().toLowerCase(),
    nomina: Number(process.env.BOOTSTRAP_ADMIN_NOMINA),
    email: normalizeEmail(process.env.BOOTSTRAP_ADMIN_EMAIL),
    password: String(process.env.BOOTSTRAP_ADMIN_PASSWORD || ""),
    name: String(process.env.BOOTSTRAP_ADMIN_NAME || "").trim(),
    last_name: String(process.env.BOOTSTRAP_ADMIN_LAST_NAME || "").trim(),
    area: String(process.env.BOOTSTRAP_ADMIN_AREA || "Administración").trim(),
  };
  const missing = Object.entries(config)
    .filter(([key, value]) => key !== "nomina" ? !value : !Number.isSafeInteger(value) || value <= 0)
    .map(([key]) => key);
  if (missing.length) {
    throw new Error(`Faltan variables válidas del administrador inicial: ${missing.join(", ")}`);
  }
  if (!USERNAME_PATTERN.test(config.username)) {
    throw new Error("BOOTSTRAP_ADMIN_USERNAME debe usar el formato nombre.apellido");
  }
  if (!/^\S+@\S+\.\S+$/.test(config.email)) {
    throw new Error("BOOTSTRAP_ADMIN_EMAIL no contiene un correo válido");
  }
  if (!isStrongPassword(config.password)) {
    throw new Error("BOOTSTRAP_ADMIN_PASSWORD debe incluir mayúscula, minúscula, número y carácter especial, con al menos 8 caracteres");
  }

  const duplicate = await User.findOne({
    $or: [{ username: config.username }, { email: config.email }, { nomina: config.nomina }],
  }).lean();
  if (duplicate) {
    throw new Error("No se creó el administrador inicial porque su usuario, correo o nómina ya pertenece a otra cuenta");
  }

  let adminRole = await Role.findOne({ name: { $regex: /^admin$/i } });
  if (!adminRole) {
    adminRole = await Role.create({
      name: "admin",
      description: "Administrador general del sistema",
      active: true,
      permissions: ALL_PERMISSION_KEYS,
      permissions_version: 1,
    });
  } else {
    adminRole.active = true;
    adminRole.permissions = ALL_PERMISSION_KEYS;
    adminRole.permissions_version = 1;
    await adminRole.save();
  }

  const escapedArea = config.area.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  let adminArea = await Area.findOne({ name: { $regex: new RegExp(`^${escapedArea}$`, "i") } });
  if (!adminArea) {
    adminArea = await Area.create({
      name: config.area,
      description: "Área administrativa inicial del sistema",
      active: true,
    });
  }

  await User.create({
    username: config.username,
    nomina: config.nomina,
    email: config.email,
    password: await bcrypt.hash(config.password, 10),
    name: config.name,
    last_name: config.last_name,
    rolId: adminRole._id,
    area: adminArea._id,
    active: true,
  });
  console.log(`Administrador inicial creado: ${config.email}`);
};
const getSystemSettings = () => SystemSetting.findOneAndUpdate(
  { key: "general" }, { $setOnInsert: { key: "general" } }, { returnDocument: "after", upsert: true, setDefaultsOnInsert: true },
);

const createMailTransport = () => {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
};

const allowedAttachmentTypes = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
]);
const uploadAttachment = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 1 },
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
      ? "El archivo supera el límite máximo permitido"
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

const getAuthorizedUser = async (userId) => {
  await ensureRolePermissions();
  return User.findById(userId).populate("rolId", "name active permissions");
};
const hasPermission = (user, permission) => Boolean(
  user && user.active !== false && user.rolId && user.rolId.active !== false &&
  (user.rolId.permissions?.includes("system.manage") || user.rolId.permissions?.includes(permission)),
);
const authorizePermission = (permission) => async (req, res, next) => {
  try {
    const user = await getAuthorizedUser(req.userId);
    if (!hasPermission(user, permission)) {
      return res.status(403).json({ status: "error", message: "No tienes permisos para realizar esta acción" });
    }
    req.authUser = user;
    next();
  } catch {
    return res.status(403).json({ status: "error", message: "No fue posible validar tus permisos" });
  }
};
const authorizeAnyPermission = (...permissions) => async (req, res, next) => {
  try {
    const user = await getAuthorizedUser(req.userId);
    if (!permissions.some((permission) => hasPermission(user, permission))) {
      return res.status(403).json({ status: "error", message: "No tienes permisos para realizar esta acción" });
    }
    req.authUser = user;
    next();
  } catch {
    return res.status(403).json({ status: "error", message: "No fue posible validar tus permisos" });
  }
};

const adminOnly = authorizePermission("system.manage");
const adminOrSupervisor = authorizePermission("reports.view");
const supportStaff = authorizePermission("work.view_all");
const usersManager = authorizePermission("users.manage");
const rolesManager = authorizePermission("roles.manage");
const catalogsManager = authorizePermission("catalogs.manage");
const inventoryManager = authorizePermission("inventory.manage");
const slaManager = authorizePermission("sla.manage");
const auditViewer = authorizePermission("audit.view");
const notificationManager = authorizePermission("notifications.manage");
const settingsManager = authorizePermission("settings.manage");
const usersReader = authorizeAnyPermission("users.manage", "work.assign");
const getWorkItemVisibility = async (userId) => {
  const user = await getAuthorizedUser(userId);
  if (!user || user.active === false || !user.rolId || user.rolId.active === false) {
    const error = new Error("La cuenta o su rol no están disponibles");
    error.status = 403;
    throw error;
  }

  if (hasPermission(user, "work.view_all")) return {};
  if (hasPermission(user, "work.view_assigned")) return { tecnico_id: userId };
  return { solicitante_id: userId };
};
const authorizeWorkItemUpdate = async (req, res, next) => {
  try {
    const user = await getAuthorizedUser(req.userId);
    if (!user || (!hasPermission(user, "work.update_status") && !hasPermission(user, "work.assign"))) {
      return res.status(403).json({ status: "error", message: "No tienes permisos para realizar esta acción" });
    }
    if (Object.prototype.hasOwnProperty.call(req.body, "estado") && !hasPermission(user, "work.update_status")) {
      return res.status(403).json({
        status: "error",
        message: "Solo un técnico puede modificar el estado de solicitudes y tickets",
      });
    }
    if (Object.prototype.hasOwnProperty.call(req.body, "tecnico_id")) {
      if (!hasPermission(user, "work.assign")) {
        return res.status(403).json({
          status: "error",
          message: "Solo un supervisor puede asignar técnicos a solicitudes y tickets",
        });
      }
      const technician = await getAuthorizedUser(req.body.tecnico_id);
      if (!hasPermission(technician, "work.receive_assignment")) {
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
  authenticate(req, res, () => usersManager(req, res, next));
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
      const appliesTo = path === "solicitudes" ? "solicitud" : path === "tickets" ? "ticket" : null;
      if (appliesTo && Object.prototype.hasOwnProperty.call(req.body, "estado") && !await findActiveCatalogValue("estado", req.body.estado, appliesTo)) {
        return res.status(400).json({ status: "error", message: "El estado seleccionado no está disponible" });
      }
      if (appliesTo && Object.prototype.hasOwnProperty.call(req.body, "prioridad") && !await findActiveCatalogValue("prioridad", req.body.prioridad, appliesTo)) {
        return res.status(400).json({ status: "error", message: "La prioridad seleccionada no está disponible" });
      }
      const previous = ["solicitudes", "tickets", "items"].includes(path)
        ? await Model.findById(getId(req)).lean()
        : null;
      if (
        path === "solicitudes" &&
        Object.prototype.hasOwnProperty.call(req.body, "tecnico_id") &&
        previous?.estado_aprobacion !== "aprobada"
      ) {
        return res.status(409).json({
          status: "error",
          message: "La solicitud debe estar aprobada antes de asignarla a un técnico",
        });
      }
      if (path === "tickets" && previous?.estado === "cerrado") {
        return res.status(409).json({ status: "error", message: "Un ticket cerrado ya no puede modificarse" });
      }
      if (
        path === "tickets" &&
        Object.prototype.hasOwnProperty.call(req.body, "estado") &&
        ["resuelto", "cerrado"].includes(String(req.body.estado).toLowerCase())
      ) {
        return res.status(409).json({
          status: "error",
          message: "Utiliza el flujo de solución y cierre para completar el ticket",
        });
      }
      const updatePayload = pick(req.body, fields);
      if (path === "roles" && Array.isArray(updatePayload.permissions)) {
        updatePayload.permissions = [...new Set(updatePayload.permissions.filter((permission) => ALL_PERMISSION_KEYS.includes(permission)))];
        updatePayload.permissions_version = 1;
      }
      if (appliesTo && req.body.prioridad && req.body.prioridad !== previous?.prioridad) {
        Object.assign(updatePayload, await buildSlaDates(req.body.prioridad, previous?.createdAt || new Date()));
      }
      if (appliesTo && req.body.estado && !previous?.first_response_at) updatePayload.first_response_at = new Date();
      const updated = await Model.findByIdAndUpdate(getId(req), updatePayload, {
        returnDocument: "after",
        runValidators: true,
      });
      if (!updated) return notFound(res, label);
      try {
        await notifyWorkItemChanges(path, previous, updated, req.userId);
      } catch (notificationError) {
        console.error("No fue posible crear la notificación:", notificationError);
      }
      if (path === "items" && previous) {
        try {
          const trackedFields = ["type", "brand", "model", "serial_number", "status"];
          const changes = Object.fromEntries(
            trackedFields
              .filter((field) => String(previous[field] ?? "") !== String(updated[field] ?? ""))
              .map((field) => [field, { previous: previous[field] ?? null, current: updated[field] ?? null }]),
          );
          if (Object.keys(changes).length) {
            const statusChanged = Boolean(changes.status);
            await EquipoEvento.create({
              inventory_id: updated._id,
              event_type: statusChanged ? "cambio_estado" : "actualizacion",
              description: statusChanged
                ? `Estado actualizado de “${changes.status.previous || "sin estado"}” a “${changes.status.current || "sin estado"}”`
                : `Información del equipo actualizada: ${Object.keys(changes).join(", ")}`,
              changes,
              performed_by: req.userId,
            });
          }
        } catch (historyError) {
          console.error("No fue posible registrar el historial del equipo:", historyError);
        }
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

app.get("/api/status", (req, res) => {
  res.status(200).json({ status: "Servidor funcionando correctamente" });
});

app.get("/api/permissions", authenticate, rolesManager, (_req, res) => {
  res.json({ status: "success", permissions: PERMISSIONS.map(([key, name, description]) => ({ key, name, description })) });
});

const getActiveCatalog = async (req, res, type, responseKey) => {
  try {
    await ensureDefaultCatalogs();
    const appliesTo = ["solicitud", "ticket"].includes(req.query.applies_to) ? req.query.applies_to : null;
    const filter = { type, active: true };
    if (appliesTo) filter.applies_to = { $in: ["ambos", appliesTo] };
    const items = await Catalogo.find(filter).sort({ order: 1, name: 1 }).lean();
    return res.json({ status: "success", [responseKey]: items.map((item) => item.key), items });
  } catch (error) {
    console.error(`No fue posible cargar el catálogo de ${responseKey}:`, error);
    return res.status(500).json({ status: "error", message: `No fue posible cargar el catálogo de ${responseKey}` });
  }
};

app.get("/api/estados", authenticate, (req, res) => getActiveCatalog(req, res, "estado", "estados"));
app.get("/api/prioridades", authenticate, (req, res) => getActiveCatalog(req, res, "prioridad", "prioridades"));

app.get("/api/catalogs", authenticate, catalogsManager, async (req, res) => {
  try {
    await ensureDefaultCatalogs();
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 20));
    const filter = {};
    if (["estado", "prioridad"].includes(req.query.type)) filter.type = req.query.type;
    const search = String(req.query.search || "").trim().slice(0, 100);
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      filter.$or = [{ key: { $regex: escaped, $options: "i" } }, { name: { $regex: escaped, $options: "i" } }];
    }
    const [items, total] = await Promise.all([
      Catalogo.find(filter).sort({ type: 1, order: 1, name: 1 }).skip((page - 1) * limit).limit(limit).lean(),
      Catalogo.countDocuments(filter),
    ]);
    return res.json({ status: "success", items, total });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "No fue posible consultar los catálogos" });
  }
});

app.post("/api/catalogs", authenticate, catalogsManager, async (req, res) => {
  try {
    const type = String(req.body.type || "").toLowerCase();
    const name = String(req.body.name || "").trim();
    const key = catalogKey(req.body.key || name);
    const appliesTo = ["ambos", "solicitud", "ticket"].includes(req.body.applies_to) ? req.body.applies_to : "ambos";
    if (!["estado", "prioridad"].includes(type) || !name || !key) {
      return res.status(400).json({ status: "error", message: "Tipo y nombre son obligatorios" });
    }
    const item = await Catalogo.create({
      type, key, name, applies_to: appliesTo,
      description: String(req.body.description || "").trim(),
      order: Math.max(0, Number(req.body.order) || 0), active: req.body.active !== false,
    });
    return res.status(201).json({ status: "success", message: "Elemento de catálogo registrado", item });
  } catch (error) {
    const status = error?.code === 11000 ? 409 : 400;
    return res.status(status).json({ status: "error", message: error?.code === 11000 ? "La clave ya existe en este catálogo" : "No fue posible registrar el elemento" });
  }
});

app.put("/api/catalogs/:id", authenticate, catalogsManager, async (req, res) => {
  try {
    const current = await Catalogo.findById(req.params.id);
    if (!current) return notFound(res, "Elemento de catálogo");
    const update = pick(req.body, ["name", "description", "applies_to", "order", "active"]);
    if (update.name !== undefined) update.name = String(update.name).trim();
    if (!update.name) return res.status(400).json({ status: "error", message: "El nombre es obligatorio" });
    if (update.applies_to && !["ambos", "solicitud", "ticket"].includes(update.applies_to)) {
      return res.status(400).json({ status: "error", message: "El ámbito no es válido" });
    }
    if (current.system && current.type === "estado" && (update.active === false || (update.applies_to !== undefined && update.applies_to !== "ambos"))) {
      return res.status(409).json({ status: "error", message: "Los estados base deben permanecer activos para solicitudes y tickets" });
    }
    const item = await Catalogo.findByIdAndUpdate(req.params.id, update, { returnDocument: "after", runValidators: true });
    return res.json({ status: "success", message: "Elemento de catálogo actualizado", item });
  } catch (error) {
    return res.status(400).json({ status: "error", message: "No fue posible actualizar el elemento" });
  }
});

app.delete("/api/catalogs/:id", authenticate, catalogsManager, async (req, res) => {
  try {
    const item = await Catalogo.findById(req.params.id);
    if (!item) return notFound(res, "Elemento de catálogo");
    if (item.system) return res.status(409).json({ status: "error", message: "Los elementos base pueden desactivarse, pero no eliminarse" });
    const field = item.type === "estado" ? "estado" : "prioridad";
    const inUse = await Promise.all([Solicitud.exists({ [field]: item.key }), Ticket.exists({ [field]: item.key })]);
    if (inUse.some(Boolean)) return res.status(409).json({ status: "error", message: "El elemento está en uso; desactívalo en lugar de eliminarlo" });
    await item.deleteOne();
    return res.json({ status: "success", message: "Elemento de catálogo eliminado" });
  } catch (error) {
    return res.status(400).json({ status: "error", message: "No fue posible eliminar el elemento" });
  }
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
    if (!isValidUsername(username)) {
      return res.status(400).json({
        status: "error",
        message: "El usuario debe tener el formato nombre.apellido, sin espacios ni caracteres especiales",
      });
    }
    const normalizedUsername = normalizeUsername(username);
    const existingUser = await User.findOne({
      $or: [{ email: String(email).trim().toLowerCase() }, { username: normalizedUsername }, { nomina }],
    });
    if (existingUser) {
      return res
        .status(400)
        .json({ status: "error", message: "El usuario ya existe" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username: normalizedUsername,
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

app.post("/api/users/import", authenticate, usersManager, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.rows) ? req.body.rows.slice(0, 200) : [];
    if (!rows.length) return res.status(400).json({ status: "error", message: "El archivo no contiene usuarios" });
    if (req.body.rows.length > 200) return res.status(413).json({ status: "error", message: "Sólo se permiten 200 usuarios por archivo" });

    const [roles, areas] = await Promise.all([
      Role.find({ active: { $ne: false } }).select("name").lean(),
      Area.find({ active: { $ne: false } }).select("name").lean(),
    ]);
    const normalizeLookup = (value) => String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim().toLowerCase();
    const roleMap = new Map(roles.flatMap((role) => [[String(role._id), role], [normalizeLookup(role.name), role]]));
    const areaMap = new Map(areas.flatMap((area) => [[String(area._id), area], [normalizeLookup(area.name), area]]));
    const usernames = new Set();
    const emails = new Set();
    const payrollNumbers = new Set();
    const candidates = [];
    const errors = [];

    rows.forEach((source, index) => {
      const rowNumber = index + 2;
      const username = normalizeUsername(source.username);
      const email = normalizeEmail(source.email);
      const payrollText = String(source.nomina ?? "").trim();
      const nomina = Number(payrollText);
      const password = String(source.password || "");
      const name = String(source.name || "").trim();
      const lastName = String(source.last_name || "").trim();
      const role = roleMap.get(String(source.role || "").trim()) || roleMap.get(normalizeLookup(source.role));
      const area = areaMap.get(String(source.area || "").trim()) || areaMap.get(normalizeLookup(source.area));
      const messages = [];
      if (!isValidUsername(username)) messages.push("Usuario inválido; usa nombre.apellido");
      if (!/^\S+@\S+\.\S+$/.test(email)) messages.push("Correo electrónico inválido");
      if (!payrollText || !Number.isSafeInteger(nomina) || nomina < 0) messages.push("Nómina inválida");
      if (!isStrongPassword(password)) messages.push("La contraseña no cumple la política de seguridad");
      if (!name) messages.push("Nombre obligatorio");
      if (!lastName) messages.push("Apellidos obligatorios");
      if (!role) messages.push("Rol inexistente o inactivo");
      if (!area) messages.push("Área inexistente o inactiva");
      if (usernames.has(username)) messages.push("Usuario repetido dentro del archivo");
      if (emails.has(email)) messages.push("Correo repetido dentro del archivo");
      if (payrollNumbers.has(nomina)) messages.push("Nómina repetida dentro del archivo");
      usernames.add(username); emails.add(email); payrollNumbers.add(nomina);
      if (messages.length) errors.push({ row: rowNumber, username, messages });
      else candidates.push({ row: rowNumber, username, email, nomina, password, name, last_name: lastName, rolId: role._id, area: area._id, active: !["false", "0", "no"].includes(normalizeLookup(source.active)) });
    });

    if (candidates.length) {
      const existing = await User.find({ $or: [
        { username: { $in: candidates.map((row) => row.username) } },
        { email: { $in: candidates.map((row) => row.email) } },
        { nomina: { $in: candidates.map((row) => row.nomina) } },
      ] }).select("username email nomina").lean();
      const existingUsernames = new Set(existing.map((user) => user.username));
      const existingEmails = new Set(existing.map((user) => user.email));
      const existingPayroll = new Set(existing.map((user) => Number(user.nomina)));
      for (let index = candidates.length - 1; index >= 0; index -= 1) {
        const candidate = candidates[index];
        const messages = [];
        if (existingUsernames.has(candidate.username)) messages.push("El usuario ya existe");
        if (existingEmails.has(candidate.email)) messages.push("El correo ya existe");
        if (existingPayroll.has(candidate.nomina)) messages.push("La nómina ya existe");
        if (messages.length) {
          errors.push({ row: candidate.row, username: candidate.username, messages });
          candidates.splice(index, 1);
        }
      }
    }

    const documents = [];
    for (let index = 0; index < candidates.length; index += 10) {
      const batch = candidates.slice(index, index + 10);
      documents.push(...await Promise.all(batch.map(async ({ row, ...candidate }) => ({ ...candidate, password: await bcrypt.hash(candidate.password, 10) }))));
    }
    if (documents.length) await User.insertMany(documents, { ordered: true });
    errors.sort((a, b) => a.row - b.row);
    return res.status(documents.length ? 201 : 400).json({
      status: documents.length ? "success" : "error",
      message: `${documents.length} usuario${documents.length === 1 ? "" : "s"} importado${documents.length === 1 ? "" : "s"}; ${errors.length} fila${errors.length === 1 ? "" : "s"} con errores`,
      imported: documents.length,
      rejected: errors.length,
      errors,
    });
  } catch (error) {
    console.error("Error al importar usuarios:", error);
    return res.status(500).json({ status: "error", message: "No fue posible completar la importación" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    await ensureRolePermissions();
    const { email, password } = req.body;
    const normalizedEmail = normalizeEmail(email);
    if (!email || !password) {
      auditAccess(req, { action: "inicio_fallido", user_email: normalizedEmail, success: false, status_code: 400, details: { reason: "campos_incompletos" } });
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    const user = await User.findOne({ email: normalizedEmail })
      .select("+failedLoginAttempts +lockUntil")
      .populate("rolId", "name active permissions")
      .populate("area", "name active");
    if (!user) {
      auditAccess(req, { action: "inicio_fallido", user_email: normalizedEmail, success: false, status_code: 400, details: { reason: "usuario_no_encontrado" } });
      return res
        .status(400)
        .json({ status: "error", message: "Usuario no encontrado" });
    }
    if (user.active === false) {
      auditAccess(req, { action: "inicio_fallido", user_id: user._id, user_email: user.email, success: false, status_code: 403, details: { reason: "cuenta_inactiva" } });
      return res.status(403).json({ status: "error", message: "La cuenta se encuentra inactiva" });
    }
    if (!user.rolId || user.rolId.active === false) {
      auditAccess(req, { action: "inicio_fallido", user_id: user._id, user_email: user.email, success: false, status_code: 403, details: { reason: "rol_no_disponible" } });
      return res.status(403).json({ status: "error", message: "El rol de la cuenta no está disponible" });
    }
    const now = new Date();
    if (user.lockUntil && user.lockUntil > now) {
      const minutes = Math.max(1, Math.ceil((user.lockUntil.getTime() - now.getTime()) / 60000));
      auditAccess(req, { action: "inicio_bloqueado", user_id: user._id, user_email: user.email, success: false, status_code: 423, details: { reason: "cuenta_bloqueada", minutes } });
      return res.status(423).json({
        status: "error",
        message: `Cuenta bloqueada temporalmente. Intenta nuevamente en ${minutes} minuto${minutes === 1 ? "" : "s"} o restablece tu contraseña.`,
        lockedUntil: user.lockUntil,
      });
    }
    if (user.lockUntil) {
      user.failedLoginAttempts = 0;
      user.lockUntil = null;
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      user.failedLoginAttempts = Number(user.failedLoginAttempts || 0) + 1;
      const shouldLock = user.failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS;
      if (shouldLock) user.lockUntil = new Date(Date.now() + LOGIN_LOCK_MS);
      await user.save({ validateBeforeSave: false });
      if (shouldLock) {
        recordAudit({ category: "seguridad", action: "cuenta_bloqueada", user_id: user._id, user_email: user.email, method: req.method, path: "/api/login", resource: "sesion", success: false, status_code: 423, ...requestAuditContext(req), details: { reason: "intentos_fallidos", failed_attempts: user.failedLoginAttempts } });
        return res.status(423).json({
          status: "error",
          message: "Cuenta bloqueada durante 15 minutos después de 3 intentos fallidos. También puedes restablecer tu contraseña.",
          lockedUntil: user.lockUntil,
        });
      }
      const remaining = MAX_FAILED_LOGIN_ATTEMPTS - user.failedLoginAttempts;
      auditAccess(req, { action: "inicio_fallido", user_id: user._id, user_email: user.email, success: false, status_code: 400, details: { reason: "contrasena_incorrecta", remaining_attempts: remaining } });
      return res.status(400).json({
        status: "error",
        message: `Contraseña incorrecta. ${remaining} intento${remaining === 1 ? "" : "s"} disponible${remaining === 1 ? "" : "s"} antes del bloqueo.`,
      });
    }
    if (user.failedLoginAttempts || user.lockUntil) {
      user.failedLoginAttempts = 0;
      user.lockUntil = null;
      await user.save({ validateBeforeSave: false });
    }
    const systemSettings = await getSystemSettings();
    if (systemSettings.maintenance_mode && !hasPermission(user, "system.manage")) {
      auditAccess(req, { action: "inicio_bloqueado", user_id: user._id, user_email: user.email, success: false, status_code: 503, details: { reason: "mantenimiento" } });
      return res.status(503).json({ status: "error", message: systemSettings.maintenance_message });
    }
    const sessionMinutes = systemSettings.session_duration_minutes;
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: `${sessionMinutes}m` },
    );

    res.cookie("token", token, {
      ...cookieOptions,
      maxAge: sessionMinutes * 60 * 1000,
    });
    const safeUser = user.toObject();
    delete safeUser.password;
    delete safeUser.failedLoginAttempts;
    delete safeUser.lockUntil;
    delete safeUser.passwordResetTokenHash;
    delete safeUser.passwordResetExpires;
    auditAccess(req, { action: "inicio_exitoso", user_id: user._id, user_email: user.email, success: true, status_code: 200 });
    return res
      .status(200)
      .json({
        status: "success",
        message: "Inicio de sesión exitoso",
        user: safeUser,
      });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    auditAccess(req, { action: "error_inicio", user_email: normalizeEmail(req.body?.email), success: false, status_code: 500, details: { reason: "error_interno" } });
    res
      .status(500)
      .json({ status: "error", message: "Error al iniciar sesión" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  const genericMessage = "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña.";
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return res.status(400).json({ status: "error", message: "El correo electrónico es obligatorio" });
    }

    const user = await User.findOne({ email });
    if (!user || user.active === false) {
      return res.json({ status: "success", message: genericMessage });
    }

    const transporter = createMailTransport();
    if (!transporter) {
      console.error("No se configuraron las variables SMTP para recuperar contraseñas");
      return res.status(503).json({
        status: "error",
        message: "El servicio de recuperación no está configurado. Contacta al administrador.",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    user.passwordResetTokenHash = crypto.createHash("sha256").update(token).digest("hex");
    user.passwordResetExpires = new Date(Date.now() + PASSWORD_RESET_MS);
    await user.save({ validateBeforeSave: false });

    const frontendUrl = String(process.env.FRONTEND_URL || "http://localhost:4200").replace(/\/$/, "");
    const resetUrl = `${frontendUrl}/reset-password?token=${encodeURIComponent(token)}`;
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: "Restablecimiento de contraseña - SWSI",
        text: `Solicitaste restablecer tu contraseña. Abre este enlace durante los próximos 30 minutos: ${resetUrl}\n\nSi no realizaste la solicitud, ignora este mensaje.`,
        html: `<p>Solicitaste restablecer tu contraseña en SWSI.</p><p><a href="${resetUrl}">Restablecer contraseña</a></p><p>El enlace estará disponible durante 30 minutos. Si no realizaste la solicitud, ignora este mensaje.</p>`,
      });
    } catch (mailError) {
      user.passwordResetTokenHash = null;
      user.passwordResetExpires = null;
      await user.save({ validateBeforeSave: false });
      throw mailError;
    }

    return res.json({ status: "success", message: genericMessage });
  } catch (error) {
    console.error("Error al solicitar recuperación de contraseña:", error);
    return res.status(500).json({ status: "error", message: "No fue posible enviar el correo de recuperación" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) {
      return res.status(400).json({ status: "error", message: "El token y la contraseña son obligatorios" });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        status: "error",
        message: "La contraseña debe tener al menos 8 caracteres, mayúscula, minúscula, número y carácter especial",
      });
    }

    const tokenHash = crypto.createHash("sha256").update(String(token)).digest("hex");
    const user = await User.findOne({
      passwordResetTokenHash: tokenHash,
      passwordResetExpires: { $gt: new Date() },
      active: { $ne: false },
    }).select("+passwordResetTokenHash +passwordResetExpires +failedLoginAttempts +lockUntil");

    if (!user) {
      return res.status(400).json({ status: "error", message: "El enlace es inválido o ha expirado" });
    }

    user.password = await bcrypt.hash(password, 10);
    user.passwordResetTokenHash = null;
    user.passwordResetExpires = null;
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    res.clearCookie("token", cookieOptions);
    recordAudit({ category: "seguridad", action: "contrasena_restaurada", user_id: user._id, user_email: user.email, method: req.method, path: "/api/reset-password", resource: "usuario", resource_id: String(user._id), success: true, status_code: 200, ...requestAuditContext(req) });
    return res.json({ status: "success", message: "Contraseña actualizada correctamente. Ya puedes iniciar sesión." });
  } catch (error) {
    console.error("Error al restablecer la contraseña:", error);
    return res.status(500).json({ status: "error", message: "No fue posible restablecer la contraseña" });
  }
});

app.get("/api/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ status: "error", message: "No autorizado" });
  }
  try {
    await ensureRolePermissions();
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId)
      .select("-password")
      .populate("rolId", "name active permissions")
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
    if (req.body.username !== undefined && !isValidUsername(req.body.username)) {
      return res.status(400).json({
        status: "error",
        message: "El usuario debe tener el formato nombre.apellido, sin espacios ni caracteres especiales",
      });
    }
    const fields = ["username", "nomina", "email", "name", "last_name", "area"];
    const update = pick(req.body, fields);
    if (update.username) update.username = normalizeUsername(update.username);
    if (req.body.password) update.password = await bcrypt.hash(req.body.password, 10);

    const user = await User.findByIdAndUpdate(req.userId, update, {
      returnDocument: "after",
      runValidators: true,
    })
      .select("-password")
      .populate("rolId", "name active permissions")
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

app.get("/api/users", authenticate, usersReader, async (req, res) => {
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
      await ensureRolePermissions();
      const roleDocuments = await Role.find(/^tecnico$/i.test(role)
        ? { $or: [{ name: rolePattern }, { permissions: "work.receive_assignment" }] }
        : { name: rolePattern }).select("_id").lean();
      if (!roleDocuments.length) {
        return res.status(200).json({ status: "success", users: [], total: 0 });
      }
      filter.rolId = { $in: roleDocuments.map((item) => item._id) };
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

app.post("/api/createArea", authenticate, catalogsManager, async (req, res) => {
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

app.get("/api/getCategories", authenticate, async (req, res) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 20));
    const search = String(req.query.search || "").trim().slice(0, 100);
    const appliesTo = ["solicitud", "ticket"].includes(req.query.applies_to) ? req.query.applies_to : null;
    const filter = {};
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      filter.$or = [{ name: { $regex: escaped, $options: "i" } }, { description: { $regex: escaped, $options: "i" } }];
    }
    if (appliesTo) {
      filter.active = { $ne: false };
      filter.applies_to = { $in: ["ambos", appliesTo] };
    }
    const [categories, total] = await Promise.all([
      Category.find(filter).sort({ name: 1 }).skip((page - 1) * limit).limit(limit).lean(),
      Category.countDocuments(filter),
    ]);
    res.status(200).json({ status: "success", category: categories, categories, total });
  } catch (error) {
    console.error("Error al obtener los datos del Categorías:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener las categorías",
    });
  }
});

app.post("/api/createCategory", authenticate, catalogsManager, async (req, res) => {
  console.log("Datos para crear la categoría: ", req.body);
  try {
    const { name, description } = req.body;
    const appliesTo = ["ambos", "solicitud", "ticket"].includes(req.body.applies_to) ? req.body.applies_to : "ambos";
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
    const newCategory = await Category.create({ name, description, applies_to: appliesTo });
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

app.get("/api/getRoles", authenticate, authorizeAnyPermission("roles.manage", "users.manage"), async (req, res) => {
  try {
    await ensureRolePermissions();
    const roles = await Role.find({}, { id: 1, name: 1, description: 1, active: 1, permissions: 1 })
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

app.post("/api/createRole", authenticate, rolesManager, async (req, res) => {
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
    const permissions = Array.isArray(req.body.permissions) ? req.body.permissions.filter((permission) => ALL_PERMISSION_KEYS.includes(permission)) : [];
    const newRole = await Role.create({ name, description, permissions, permissions_version: 1 });
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

app.get("/api/getRolesForUser", authenticate, usersManager, async (req, res) => {
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

app.get("/api/getItems", authenticate, inventoryManager, async (req, res) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const maxLimit = req.query.available === "true" ? 500 : 100;
    const limit = Math.min(maxLimit, Math.max(1, Number.parseInt(req.query.limit, 10) || 10));
    const search = String(req.query.search || "").trim().slice(0, 100);
    const filter = {};
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escaped, "i");
      const assignedUsers = await User.find({
        $or: [{ username: regex }, { name: regex }, { last_name: regex }, { email: regex }],
      }).select("_id").limit(100).lean();
      filter.$or = [
        { type: regex },
        { brand: regex },
        { model: regex },
        { serial_number: regex },
        { status: regex },
        { assigned_to: { $in: assignedUsers.map((user) => user._id) } },
      ];
      if (/^\d+$/.test(search)) filter.$or.push({ id: Number(search) });
    }
    if (req.query.status) filter.status = String(req.query.status).trim();
    if (req.query.available === "true") {
      filter.assigned_to = null;
      filter.status = { $nin: [/^baja$/i, /^mantenimiento$/i] };
    }
    const [items, total] = await Promise.all([
      Inventario.find(filter)
        .populate("assigned_to", "username name last_name email")
        .sort({ id: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Inventario.countDocuments(filter),
    ]);
    res.status(200).json({ status: "success", items, total, page, limit });
  } catch (error) {
    console.error("Error al obtener los datos del Dispositivos:", error);
    res.status(500).json({
      status: "error",
      message: "Error al obtener los datos de inventario",
    });
  }
});

app.post("/api/createItem", authenticate, inventoryManager, async (req, res) => {
  try {
    const { type, brand, model, serial_number, status, assigned_to, asigned_to } = req.body;
    const assignedTo = assigned_to || asigned_to;
    if (!type || !brand || !serial_number || !model) {
      return res.status(400).json({
        status: "error",
        message: "Los campos son obligatorios",
      });
    }
    const existingItem = await Inventario.findOne({ serial_number }).maxTimeMS(10000);
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
    res
      .status(201)
      .json({ status: "success", message: "Dispositivo registrado exitosamente", item: newItem });
  } catch (error) {
    console.error("Error al registrar el dispositivo:", error);
    const duplicate = error?.code === 11000;
    res
      .status(duplicate ? 409 : 500)
      .json({
        status: "error",
        message: duplicate
          ? "Ya existe un equipo con el mismo número de serie o consecutivo"
          : "Error al registrar el dispositivo",
      });
  }
});

app.post("/api/inventory/:id/maintenance", authenticate, inventoryManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ status: "error", message: "El identificador del equipo no es válido" });
    }
    const maintenanceType = String(req.body?.maintenance_type || "").trim().toLowerCase();
    const description = String(req.body?.description || "").trim();
    const provider = String(req.body?.provider || "").trim();
    const result = String(req.body?.result || "").trim();
    const status = String(req.body?.status || "completado").trim().toLowerCase();
    const cost = Number(req.body?.cost || 0);
    const maintenanceDate = req.body?.maintenance_date ? new Date(req.body.maintenance_date) : new Date();

    if (!["preventivo", "correctivo"].includes(maintenanceType)) {
      return res.status(400).json({ status: "error", message: "El tipo de mantenimiento no es válido" });
    }
    if (!description) {
      return res.status(400).json({ status: "error", message: "La descripción del mantenimiento es obligatoria" });
    }
    if (!["programado", "en progreso", "completado"].includes(status)) {
      return res.status(400).json({ status: "error", message: "El estado del mantenimiento no es válido" });
    }
    if (!Number.isFinite(cost) || cost < 0) {
      return res.status(400).json({ status: "error", message: "El costo no es válido" });
    }
    if (Number.isNaN(maintenanceDate.getTime())) {
      return res.status(400).json({ status: "error", message: "La fecha de mantenimiento no es válida" });
    }

    const item = await Inventario.findById(req.params.id);
    if (!item) return notFound(res, "Equipo");
    const maintenance = await Mantenimiento.create({
      inventory_id: item._id,
      maintenance_type: maintenanceType,
      description,
      provider,
      cost,
      maintenance_date: maintenanceDate,
      result,
      status,
      registered_by: req.userId,
    });

    if (status === "en progreso") {
      item.status = "mantenimiento";
      await item.save();
    } else if (status === "completado" && String(item.status || "").toLowerCase() === "mantenimiento") {
      item.status = item.assigned_to ? "Asignado" : "activo";
      await item.save();
    }

    return res.status(201).json({
      status: "success",
      message: "Mantenimiento registrado correctamente",
      maintenance,
    });
  } catch (error) {
    console.error("Error al registrar el mantenimiento:", error);
    return res.status(400).json({ status: "error", message: "No fue posible registrar el mantenimiento" });
  }
});

app.get("/api/inventory/:id/history", authenticate, inventoryManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ status: "error", message: "El identificador del equipo no es válido" });
    }
    const item = await Inventario.findById(req.params.id)
      .populate("assigned_to", "username name last_name")
      .lean();
    if (!item) return notFound(res, "Equipo");

    const [events, assignments, maintenances] = await Promise.all([
      EquipoEvento.find({ inventory_id: item._id })
        .populate("performed_by", "username name last_name")
        .sort({ event_date: -1 })
        .lean(),
      Asignacion.find({ inventory_id: item._id })
        .populate("user_id", "username name last_name")
        .populate("assigned_by", "username name last_name")
        .sort({ assigned_at: -1 })
        .lean(),
      Mantenimiento.find({ inventory_id: item._id })
        .populate("registered_by", "username name last_name")
        .sort({ maintenance_date: -1 })
        .lean(),
    ]);

    const timeline = [
      {
        type: "registro",
        title: "Equipo registrado",
        description: `${item.type} ${item.brand} ${item.model} - Serie ${item.serial_number}`,
        date: item.createdAt,
        actor: null,
      },
      ...events.map((event) => ({
        type: event.event_type,
        title: event.event_type === "cambio_estado" ? "Cambio de estado" : "Equipo actualizado",
        description: event.description,
        date: event.event_date,
        actor: event.performed_by,
        changes: event.changes,
      })),
      ...assignments.flatMap((assignment) => {
        const entries = [{
          type: "asignacion",
          title: "Equipo asignado",
          description: `Asignado a ${assignment.user_id?.username || "usuario"}${assignment.notes ? ` - ${assignment.notes}` : ""}`,
          date: assignment.assigned_at,
          actor: assignment.assigned_by,
        }];
        if (assignment.returned_at) {
          entries.push({
            type: "devolucion",
            title: "Equipo devuelto",
            description: assignment.return_notes || `Devuelto por ${assignment.user_id?.username || "usuario"}`,
            date: assignment.returned_at,
            actor: assignment.assigned_by,
          });
        }
        return entries;
      }),
      ...maintenances.map((maintenance) => ({
        type: "mantenimiento",
        title: `Mantenimiento ${maintenance.maintenance_type}`,
        description: [
          maintenance.description,
          `Estado: ${maintenance.status}`,
          maintenance.provider ? `Proveedor: ${maintenance.provider}` : "",
          maintenance.result ? `Resultado: ${maintenance.result}` : "",
          `Costo: $${Number(maintenance.cost || 0).toFixed(2)}`,
        ].filter(Boolean).join(" - "),
        date: maintenance.maintenance_date,
        actor: maintenance.registered_by,
      })),
    ].sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

    return res.json({ status: "success", item, timeline });
  } catch (error) {
    console.error("Error al obtener el historial del equipo:", error);
    return res.status(400).json({ status: "error", message: "No fue posible obtener el historial del equipo" });
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
        .populate("category_id", "name description applies_to")
        .populate("solicitante_id", "username name last_name")
        .populate("tecnico_id", "username name last_name")
        .populate("solucion_por", "username name last_name")
        .populate("escalamientos.tecnico_id", "username name last_name")
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
    const { titulo, descripcion, prioridad, category } = req.body;
    if (!titulo || !descripcion || !prioridad || !category) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    if (!await findActiveCatalogValue("prioridad", prioridad, "ticket")) {
      return res.status(400).json({ status: "error", message: "La prioridad seleccionada no está disponible" });
    }
    if (!mongoose.isValidObjectId(category)) return res.status(400).json({ status: "error", message: "La categoría seleccionada no es válida" });
    const selectedCategory = await Category.findOne({ _id: category, active: { $ne: false }, applies_to: { $in: ["ambos", "ticket"] } });
    if (!selectedCategory) return res.status(400).json({ status: "error", message: "La categoría seleccionada no está disponible para tickets" });
    const slaDates = await buildSlaDates(prioridad);
    const ticket = await Ticket.create({
      titulo,
      category_id: selectedCategory._id,
      descripcion,
      prioridad,
      solicitante_id: req.userId,
      ...slaDates,
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

app.patch("/api/tickets/:id/solution", authenticate, authorizePermission("tickets.solve"), async (req, res) => {
  try {
    const solucion = String(req.body?.solucion || "").trim();
    if (!solucion) {
      return res.status(400).json({ status: "error", message: "La descripción de la solución es obligatoria" });
    }
    if (solucion.length > 4000) {
      return res.status(400).json({ status: "error", message: "La solución no puede superar 4000 caracteres" });
    }

    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return notFound(res, "Ticket");
    if (String(ticket.tecnico_id || "") !== String(req.userId)) {
      return res.status(403).json({ status: "error", message: "Solo el técnico asignado puede registrar la solución" });
    }
    if (ticket.estado === "cerrado") {
      return res.status(409).json({ status: "error", message: "El ticket ya está cerrado" });
    }

    ticket.solucion = solucion;
    ticket.solucion_por = req.userId;
    ticket.fecha_solucion = new Date();
    ticket.first_response_at ||= new Date();
    ticket.estado = "resuelto";
    await ticket.save();

    if (ticket.solicitante_id && String(ticket.solicitante_id) !== String(req.userId)) {
      try {
        await Notificacion.create({
          recipient: ticket.solicitante_id,
          type: "solution",
          title: "Ticket resuelto",
          message: `El ticket ${ticket.folio} tiene una solución disponible para revisión y cierre.`,
          entity_type: "ticket",
          entity_id: ticket._id,
        });
      } catch (notificationError) {
        console.error("No fue posible notificar la solución del ticket:", notificationError);
      }
    }
    return res.json({ status: "success", message: "Solución registrada correctamente", ticket });
  } catch (error) {
    console.error("Error al registrar la solución:", error);
    return res.status(error?.name === "CastError" ? 400 : 500).json({
      status: "error",
      message: "No fue posible registrar la solución",
    });
  }
});

app.patch("/api/tickets/:id/escalate", authenticate, authorizePermission("tickets.escalate"), async (req, res) => {
  try {
    const motivo = String(req.body?.motivo || "").trim();
    if (!motivo) {
      return res.status(400).json({ status: "error", message: "El motivo del escalamiento es obligatorio" });
    }
    if (motivo.length > 2000) {
      return res.status(400).json({ status: "error", message: "El motivo no puede superar 2000 caracteres" });
    }

    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return notFound(res, "Ticket");
    if (String(ticket.tecnico_id || "") !== String(req.userId)) {
      return res.status(403).json({ status: "error", message: "Solo el técnico asignado puede escalar el ticket" });
    }
    if (["resuelto", "cerrado"].includes(ticket.estado)) {
      return res.status(409).json({ status: "error", message: "Un ticket resuelto o cerrado no puede escalarse" });
    }

    ticket.escalamientos.push({ motivo, tecnico_id: req.userId, fecha: new Date() });
    ticket.first_response_at ||= new Date();
    ticket.tecnico_id = null;
    ticket.estado = "pendiente";
    await ticket.save();

    const supervisorRoles = await Role.find({ name: /^supervisor$/i }).select("_id").lean();
    const supervisors = await User.find({
      rolId: { $in: supervisorRoles.map((role) => role._id) },
      active: { $ne: false },
    }).select("_id").lean();
    const notifications = supervisors.map((supervisor) => ({
      recipient: supervisor._id,
      type: "escalation",
      title: "Ticket escalado",
      message: `El ticket ${ticket.folio} requiere reasignación. Motivo: ${motivo}`,
      entity_type: "ticket",
      entity_id: ticket._id,
    }));
    if (ticket.solicitante_id && String(ticket.solicitante_id) !== String(req.userId)) {
      notifications.push({
        recipient: ticket.solicitante_id,
        type: "escalation",
        title: "Ticket escalado",
        message: `El ticket ${ticket.folio} fue escalado para continuar su atención.`,
        entity_type: "ticket",
        entity_id: ticket._id,
      });
    }
    if (notifications.length) {
      try {
        await Notificacion.insertMany(notifications);
      } catch (notificationError) {
        console.error("No fue posible notificar el escalamiento:", notificationError);
      }
    }
    return res.json({ status: "success", message: "Ticket escalado correctamente", ticket });
  } catch (error) {
    console.error("Error al escalar el ticket:", error);
    return res.status(error?.name === "CastError" ? 400 : 500).json({
      status: "error",
      message: "No fue posible escalar el ticket",
    });
  }
});

app.patch("/api/tickets/:id/close", authenticate, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return notFound(res, "Ticket");
    if (String(ticket.solicitante_id || "") !== String(req.userId)) {
      return res.status(403).json({ status: "error", message: "Solo el usuario que creó el ticket puede cerrarlo" });
    }
    if (ticket.estado !== "resuelto" || !ticket.solucion) {
      return res.status(409).json({ status: "error", message: "El ticket debe tener una solución antes de cerrarse" });
    }

    ticket.estado = "cerrado";
    ticket.fecha_cierre = new Date();
    await ticket.save();
    if (ticket.tecnico_id && String(ticket.tecnico_id) !== String(req.userId)) {
      try {
        await Notificacion.create({
          recipient: ticket.tecnico_id,
          type: "closure",
          title: "Ticket cerrado",
          message: `El usuario aceptó la solución y cerró el ticket ${ticket.folio}.`,
          entity_type: "ticket",
          entity_id: ticket._id,
        });
      } catch (notificationError) {
        console.error("No fue posible notificar el cierre del ticket:", notificationError);
      }
    }
    return res.json({ status: "success", message: "Ticket cerrado correctamente", ticket });
  } catch (error) {
    console.error("Error al cerrar el ticket:", error);
    return res.status(error?.name === "CastError" ? 400 : 500).json({
      status: "error",
      message: "No fue posible cerrar el ticket",
    });
  }
});

app.post("/api/tickets/:id/survey", authenticate, async (req, res) => {
  try {
    const calificacion = Number(req.body?.calificacion);
    const comentario = String(req.body?.comentario || "").trim();
    if (!Number.isInteger(calificacion) || calificacion < 1 || calificacion > 5) {
      return res.status(400).json({ status: "error", message: "La calificación debe estar entre 1 y 5" });
    }
    if (comentario.length > 2000) {
      return res.status(400).json({ status: "error", message: "El comentario no puede superar 2000 caracteres" });
    }

    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return notFound(res, "Ticket");
    if (String(ticket.solicitante_id || "") !== String(req.userId)) {
      return res.status(403).json({ status: "error", message: "Solo el usuario que creó el ticket puede calificarlo" });
    }
    if (ticket.estado !== "cerrado") {
      return res.status(409).json({ status: "error", message: "El ticket debe estar cerrado antes de calificarlo" });
    }
    if (ticket.encuesta?.calificacion) {
      return res.status(409).json({ status: "error", message: "La encuesta de este ticket ya fue respondida" });
    }

    ticket.encuesta = { calificacion, comentario, fecha: new Date() };
    await ticket.save();
    return res.json({ status: "success", message: "Gracias por compartir tu opinión", ticket });
  } catch (error) {
    console.error("Error al registrar la encuesta:", error);
    return res.status(error?.name === "CastError" ? 400 : 500).json({
      status: "error",
      message: "No fue posible registrar la encuesta",
    });
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
        .populate("category_id", "name description applies_to")
        .populate("solicitante_id", "username name last_name")
        .populate("tecnico_id", "username name last_name")
        .populate("supervisor_id", "username name last_name")
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
    const { category, descripcion, comentarios, area, prioridad } = req.body;
    if (!category || !descripcion || !area || !prioridad) {
      return res.status(400).json({
        status: "error",
        message: "Todos los campos son obligatorios",
      });
    }
    if (!await findActiveCatalogValue("prioridad", prioridad, "solicitud")) {
      return res.status(400).json({ status: "error", message: "La prioridad seleccionada no está disponible" });
    }
    if (!mongoose.isValidObjectId(category)) return res.status(400).json({ status: "error", message: "La categoría seleccionada no es válida" });
    const selectedCategory = await Category.findOne({ _id: category, active: { $ne: false }, applies_to: { $in: ["ambos", "solicitud"] } });
    if (!selectedCategory) return res.status(400).json({ status: "error", message: "La categoría seleccionada no está disponible para solicitudes" });
    if (!mongoose.isValidObjectId(area)) {
      return res.status(400).json({ status: "error", message: "El área seleccionada no es válida" });
    }
    const selectedArea = await Area.exists({ _id: area, active: { $ne: false } });
    if (!selectedArea) {
      return res.status(400).json({ status: "error", message: "El área seleccionada no está disponible" });
    }
    const slaDates = await buildSlaDates(prioridad);
    const solicitud = await Solicitud.create({
      tipo: selectedCategory.name,
      category_id: selectedCategory._id,
      descripcion,
      comentarios,
      area,
      prioridad,
      solicitante_id: req.userId,
      ...slaDates,
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

app.patch(
  "/api/solicitudes/:id/decision",
  authenticate,
  authorizePermission("requests.decide"),
  async (req, res) => {
    try {
      const decision = String(req.body?.decision || "").trim().toLowerCase();
      const motivo = String(req.body?.motivo || "").trim();
      if (!["aprobada", "rechazada"].includes(decision)) {
        return res.status(400).json({ status: "error", message: "La decisión no es válida" });
      }
      if (decision === "rechazada" && !motivo) {
        return res.status(400).json({ status: "error", message: "El motivo de rechazo es obligatorio" });
      }
      if (motivo.length > 1000) {
        return res.status(400).json({ status: "error", message: "El motivo no puede superar 1000 caracteres" });
      }

      const current = await Solicitud.findById(req.params.id).lean();
      if (!current) return notFound(res, "Solicitud");
      if (current.estado_aprobacion && current.estado_aprobacion !== "pendiente") {
        return res.status(409).json({
          status: "error",
          message: `La solicitud ya fue ${current.estado_aprobacion}`,
        });
      }

      const reviewedAt = new Date();
      const update = {
        estado_aprobacion: decision,
        supervisor_id: req.userId,
        fecha_revision: reviewedAt,
        fecha_aprobacion: decision === "aprobada" ? reviewedAt : null,
        motivo_rechazo: decision === "rechazada" ? motivo : null,
      };
      if (decision === "rechazada") update.tecnico_id = null;

      const solicitud = await Solicitud.findOneAndUpdate(
        {
          _id: req.params.id,
          $or: [
            { estado_aprobacion: "pendiente" },
            { estado_aprobacion: { $exists: false } },
          ],
        },
        { $set: update },
        { returnDocument: "after", runValidators: true },
      )
        .populate("solicitante_id", "username name last_name")
        .populate("supervisor_id", "username name last_name");

      if (!solicitud) {
        return res.status(409).json({ status: "error", message: "La solicitud ya fue revisada" });
      }

      if (solicitud.solicitante_id) {
        try {
          await Notificacion.create({
            recipient: solicitud.solicitante_id._id || solicitud.solicitante_id,
            type: "decision",
            title: `Solicitud ${decision}`,
            message: decision === "aprobada"
              ? `La solicitud ${solicitud.folio} fue aprobada.`
              : `La solicitud ${solicitud.folio} fue rechazada. Motivo: ${motivo}`,
            entity_type: "solicitud",
            entity_id: solicitud._id,
          });
        } catch (notificationError) {
          console.error("No fue posible notificar la decisión de la solicitud:", notificationError);
        }
      }

      return res.json({
        status: "success",
        message: `Solicitud ${decision} correctamente`,
        solicitud,
      });
    } catch (error) {
      console.error("Error al registrar la decisión de la solicitud:", error);
      const status = error?.name === "CastError" ? 400 : 500;
      return res.status(status).json({
        status: "error",
        message: status === 400 ? "El identificador de la solicitud no es válido" : "No fue posible registrar la decisión",
      });
    }
  },
);

app.put("/api/users/:id", authenticate, usersManager, async (req, res) => {
  try {
    if (req.body.username !== undefined && !isValidUsername(req.body.username)) {
      return res.status(400).json({
        status: "error",
        message: "El usuario debe tener el formato nombre.apellido, sin espacios ni caracteres especiales",
      });
    }
    const fields = ["username", "nomina", "email", "name", "last_name", "rolId", "area", "active"];
    const update = pick(req.body, fields);
    if (update.username) update.username = normalizeUsername(update.username);
    if (req.body.password) update.password = await bcrypt.hash(req.body.password, 10);
    const user = await User.findByIdAndUpdate(req.params.id, update, { returnDocument: "after", runValidators: true })
      .select("-password");
    if (!user) return notFound(res, "Usuario");
    res.json({ status: "success", message: "Usuario actualizado correctamente", user });
  } catch (error) {
    const status = error?.code === 11000 ? 409 : 400;
    res.status(status).json({ status: "error", message: "No fue posible actualizar el usuario" });
  }
});

app.delete("/api/users/:id", authenticate, usersManager, async (req, res) => {
  if (String(req.userId) === req.params.id) {
    return res.status(400).json({ status: "error", message: "No puedes eliminar tu propia cuenta" });
  }
  try {
    const references = await Promise.all([
      Inventario.exists({ assigned_to: req.params.id }),
      Asignacion.exists({ $or: [{ user_id: req.params.id }, { assigned_by: req.params.id }] }),
      Solicitud.exists({ $or: [{ solicitante_id: req.params.id }, { supervisor_id: req.params.id }, { tecnico_id: req.params.id }] }),
      Ticket.exists({ $or: [{ solicitante_id: req.params.id }, { supervisor_id: req.params.id }, { tecnico_id: req.params.id }] }),
      Mantenimiento.exists({ registered_by: req.params.id }),
      EquipoEvento.exists({ performed_by: req.params.id }),
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
  catalogsManager,
  catalogsManager,
  async (id) =>
    (await User.exists({ area: id })) || (await Solicitud.exists({ area: id }))
      ? "El área tiene registros relacionados; desactívala en lugar de eliminarla"
      : null,
);
registerCrudRoutes(
  "categories",
  Category,
  ["name", "description", "applies_to", "active"],
  "Categoría",
  catalogsManager,
  catalogsManager,
  async (id) => (await Solicitud.exists({ category_id: id })) || (await Ticket.exists({ category_id: id }))
    ? "La categoría tiene registros relacionados; desactívala en lugar de eliminarla"
    : null,
);
registerCrudRoutes(
  "roles",
  Role,
  ["name", "description", "active", "permissions"],
  "Rol",
  rolesManager,
  rolesManager,
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
  inventoryManager,
  inventoryManager,
  async (id) =>
    (await Asignacion.exists({ inventory_id: id })) ||
    (await Mantenimiento.exists({ inventory_id: id })) ||
    (await EquipoEvento.exists({ inventory_id: id }))
      ? "El equipo tiene historial relacionado; cámbialo a estado Baja en lugar de eliminarlo"
      : null,
);
registerCrudRoutes(
  "solicitudes",
  Solicitud,
  ["tipo", "descripcion", "area", "prioridad", "estado", "comentarios", "tecnico_id", "fecha_cierre"],
  "Solicitud",
  authorizeWorkItemUpdate,
  adminOnly,
);
registerCrudRoutes(
  "tickets",
  Ticket,
  ["titulo", "descripcion", "prioridad", "estado", "comentarios", "supervisor_id", "tecnico_id"],
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
      const systemSettings = await getSystemSettings();
      if (req.file.size > systemSettings.max_attachment_mb * 1024 * 1024) {
        return res.status(413).json({ status: "error", message: `El archivo no puede superar ${systemSettings.max_attachment_mb} MB` });
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

app.get("/api/assignments", authenticate, inventoryManager, async (req, res) => {
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

app.post("/api/assignments", authenticate, inventoryManager, async (req, res) => {
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
    if (["baja", "mantenimiento"].includes(String(item.status || "").toLowerCase())) {
      return res.status(409).json({
        status: "error",
        message: "Un equipo dado de baja o en mantenimiento no puede asignarse",
      });
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

app.put("/api/assignments/:id", authenticate, inventoryManager, async (req, res) => {
  try {
    const assignment = await Asignacion.findByIdAndUpdate(
      req.params.id,
      pick(req.body, ["notes", "return_notes"]),
      { returnDocument: "after", runValidators: true },
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

app.delete("/api/assignments/:id", authenticate, inventoryManager, async (req, res) => {
  try {
    const assignment = await Asignacion.findById(req.params.id);
    if (!assignment) return notFound(res, "Asignación");
    if (!assignment.active) {
      return res.status(409).json({
        status: "error",
        message: "Las asignaciones históricas no pueden eliminarse",
      });
    }

    assignment.active = false;
    assignment.returned_at = new Date();
    assignment.return_notes = assignment.return_notes || "Asignación cancelada por el administrador";
    await assignment.save();
    await Inventario.updateOne(
      { _id: assignment.inventory_id, assigned_to: assignment.user_id },
      { $set: { assigned_to: null, status: "Disponible" } },
    );
    res.json({ status: "success", message: "Asignación finalizada y conservada en el historial" });
  } catch (error) {
    res.status(400).json({
      status: "error",
      message: "No fue posible eliminar la asignación",
    });
  }
});

app.patch("/api/assignments/:id/return", authenticate, inventoryManager, async (req, res) => {
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
    const type = ["solicitudes", "tickets", "tecnicos", "inventario"].includes(req.query.type)
      ? req.query.type
      : "solicitudes";
    const exporting = req.query.export === "true";
    const page = exporting ? 1 : Math.max(Number(req.query.page) || 1, 1);
    const limit = exporting ? 10000 : Math.min(Math.max(Number(req.query.limit) || 10, 1), 100);
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
    const [solicitudSummary, ticketSummary, inventoryStatusSummary, inventoryTypeSummary] = await Promise.all([
      Solicitud.aggregate([
        { $match: baseMatch },
        { $group: { _id: "$estado", total: { $sum: 1 }, unassigned: { $sum: { $cond: [{ $eq: [{ $ifNull: ["$tecnico_id", null] }, null] }, 1, 0] } } } },
      ]),
      Ticket.aggregate([
        { $match: baseMatch },
        { $group: { _id: "$estado", total: { $sum: 1 }, unassigned: { $sum: { $cond: [{ $eq: [{ $ifNull: ["$tecnico_id", null] }, null] }, 1, 0] } } } },
      ]),
      Inventario.aggregate([
        { $match: baseMatch },
        {
          $group: {
            _id: { $toLower: { $ifNull: ["$status", "sin estado"] } },
            total: { $sum: 1 },
            assigned: { $sum: { $cond: [{ $ne: [{ $ifNull: ["$assigned_to", null] }, null] }, 1, 0] } },
          },
        },
        { $sort: { total: -1, _id: 1 } },
      ]),
      Inventario.aggregate([
        { $match: baseMatch },
        { $group: { _id: { $ifNull: ["$type", "Sin tipo"] }, total: { $sum: 1 } } },
        { $sort: { total: -1, _id: 1 } },
      ]),
    ]);
    const sumTotals = (groups) => groups.reduce(
      (result, group) => ({ total: result.total + group.total, unassigned: result.unassigned + group.unassigned }),
      { total: 0, unassigned: 0 },
    );
    const solicitudTotals = sumTotals(solicitudSummary);
    const ticketTotals = sumTotals(ticketSummary);
    const inventoryTotal = inventoryStatusSummary.reduce((total, item) => total + item.total, 0);
    const inventoryAssigned = inventoryStatusSummary.reduce((total, item) => total + item.assigned, 0);
    const summary = {
      solicitudes: solicitudTotals.total,
      tickets: ticketTotals.total,
      sin_asignar: solicitudTotals.unassigned + ticketTotals.unassigned,
      cerrados: [...solicitudSummary, ...ticketSummary]
        .filter((item) => ["resuelto", "cerrado"].includes(item._id))
        .reduce((total, item) => total + item.total, 0),
      estados_solicitudes: solicitudSummary.map((item) => ({ estado: item._id, total: item.total })),
      estados_tickets: ticketSummary.map((item) => ({ estado: item._id, total: item.total })),
      inventario: inventoryTotal,
      inventario_asignado: inventoryAssigned,
      inventario_disponible: Math.max(0, inventoryTotal - inventoryAssigned),
      inventario_baja: inventoryStatusSummary
        .filter((item) => item._id === "baja")
        .reduce((total, item) => total + item.total, 0),
      estados_inventario: inventoryStatusSummary.map((item) => ({ estado: item._id, total: item.total })),
      tipos_inventario: inventoryTypeSummary.map((item) => ({ estado: item._id, total: item.total })),
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
      return res.json({ status: "success", type, summary, rows, total, exportLimit: exporting ? limit : undefined });
    }

    if (type === "inventario") {
      const match = { ...baseMatch };
      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        match.$or = ["type", "brand", "model", "serial_number", "status"].map((field) => ({
          [field]: { $regex: escaped, $options: "i" },
        }));
      }
      const [rows, total] = await Promise.all([
        Inventario.find(match)
          .populate("assigned_to", "username name last_name")
          .sort({ id: 1 })
          .skip((page - 1) * limit)
          .limit(limit)
          .lean(),
        Inventario.countDocuments(match),
      ]);
      return res.json({ status: "success", type, summary, rows, total, exportLimit: exporting ? limit : undefined });
    }

    await ensureRolePermissions();
    const technicianRoles = await Role.find({ permissions: "work.receive_assignment" }).select("_id").lean();
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
    return res.json({ status: "success", type, summary, rows, total, exportLimit: exporting ? limit : undefined });
  } catch (error) {
    console.error("Error al generar el reporte:", error);
    res.status(500).json({ status: "error", message: "No fue posible generar el reporte" });
  }
});

app.get("/api/sla-policies", authenticate, adminOrSupervisor, async (req, res) => {
  try {
    await Promise.all([ensureDefaultCatalogs(), ensureDefaultSlaPolicies()]);
    const [priorities, policies] = await Promise.all([
      Catalogo.find({ type: "prioridad" }).sort({ order: 1 }).lean(),
      SlaPolicy.find().lean(),
    ]);
    const policyMap = new Map(policies.map((policy) => [policy.priority, policy]));
    return res.json({ status: "success", policies: priorities.map((priority) => ({ ...priority, policy: policyMap.get(priority.key) || null })) });
  } catch {
    return res.status(500).json({ status: "error", message: "No fue posible consultar las políticas SLA" });
  }
});

app.put("/api/sla-policies/:priority", authenticate, slaManager, async (req, res) => {
  try {
    const priority = String(req.params.priority || "").toLowerCase();
    const responseHours = Number(req.body.response_hours);
    const resolutionHours = Number(req.body.resolution_hours);
    const warningPercent = Number(req.body.warning_percent);
    if (!await Catalogo.exists({ type: "prioridad", key: priority })) return notFound(res, "Prioridad");
    if (!(responseHours > 0) || !(resolutionHours >= responseHours) || !(warningPercent > 0 && warningPercent < 100)) {
      return res.status(400).json({ status: "error", message: "Los tiempos SLA o el porcentaje de advertencia no son válidos" });
    }
    const policy = await SlaPolicy.findOneAndUpdate(
      { priority },
      { response_hours: responseHours, resolution_hours: resolutionHours, warning_percent: warningPercent, active: req.body.active !== false },
      { returnDocument: "after", upsert: true, runValidators: true },
    );
    return res.json({ status: "success", message: "Política SLA actualizada", policy });
  } catch {
    return res.status(400).json({ status: "error", message: "No fue posible actualizar la política SLA" });
  }
});

app.get("/api/system-settings", authenticate, async (_req, res) => {
  try {
    const settings = await getSystemSettings();
    return res.json({ status: "success", settings });
  } catch {
    return res.status(500).json({ status: "error", message: "No fue posible consultar los parámetros generales" });
  }
});

app.put("/api/system-settings", authenticate, settingsManager, async (req, res) => {
  try {
    const update = pick(req.body, [
      "system_name", "organization_name", "support_email", "timezone", "date_format", "default_page_size",
      "max_attachment_mb", "session_duration_minutes", "maintenance_mode", "maintenance_message",
    ]);
    if (!String(update.system_name || "").trim()) return res.status(400).json({ status: "error", message: "El nombre del sistema es obligatorio" });
    if (update.support_email && !/^\S+@\S+\.\S+$/.test(String(update.support_email))) return res.status(400).json({ status: "error", message: "El correo de soporte no es válido" });
    if (update.maintenance_mode && !String(update.maintenance_message || "").trim()) return res.status(400).json({ status: "error", message: "Escribe un mensaje de mantenimiento" });
    update.updated_by = req.userId;
    const settings = await SystemSetting.findOneAndUpdate(
      { key: "general" }, { $set: update, $setOnInsert: { key: "general" } }, { returnDocument: "after", upsert: true, runValidators: true, setDefaultsOnInsert: true },
    );
    return res.json({ status: "success", message: "Parámetros generales actualizados", settings });
  } catch (error) {
    return res.status(400).json({ status: "error", message: error?.message || "No fue posible actualizar los parámetros" });
  }
});

app.get("/api/notification-settings", authenticate, async (_req, res) => {
  try {
    const settings = await getGlobalNotificationSettings();
    return res.json({ status: "success", settings });
  } catch {
    return res.status(500).json({ status: "error", message: "No fue posible consultar la configuración de notificaciones" });
  }
});

app.put("/api/notification-settings", authenticate, notificationManager, async (req, res) => {
  try {
    const update = {};
    for (const field of notificationPreferenceFields) {
      if (typeof req.body?.events?.[field] === "boolean") update[`events.${field}`] = req.body.events[field];
    }
    if (typeof req.body.allow_user_preferences === "boolean") update.allow_user_preferences = req.body.allow_user_preferences;
    const pollingSeconds = Number(req.body.polling_seconds);
    const retentionDays = Number(req.body.retention_days);
    if (!Number.isInteger(pollingSeconds) || pollingSeconds < 15 || pollingSeconds > 300) {
      return res.status(400).json({ status: "error", message: "El intervalo debe estar entre 15 y 300 segundos" });
    }
    if (!Number.isInteger(retentionDays) || retentionDays < 7 || retentionDays > 730) {
      return res.status(400).json({ status: "error", message: "La retención debe estar entre 7 y 730 días" });
    }
    update.polling_seconds = pollingSeconds;
    update.retention_days = retentionDays;
    update.updated_by = req.userId;
    const settings = await NotificationSetting.findOneAndUpdate(
      { key: "global" }, { $set: update, $setOnInsert: { key: "global" } }, { returnDocument: "after", upsert: true, runValidators: true, setDefaultsOnInsert: true },
    );
    return res.json({ status: "success", message: "Configuración global actualizada", settings });
  } catch (error) {
    return res.status(400).json({ status: "error", message: "No fue posible actualizar la configuración" });
  }
});

app.get("/api/notification-preferences", authenticate, async (req, res) => {
  try {
    const preferences = await getNotificationPreferences(req.userId);
    return res.json({ status: "success", preferences });
  } catch {
    return res.status(500).json({ status: "error", message: "No fue posible consultar las preferencias" });
  }
});

app.put("/api/notification-preferences", authenticate, async (req, res) => {
  try {
    const globalSettings = await getGlobalNotificationSettings();
    if (!globalSettings.allow_user_preferences) {
      return res.status(403).json({ status: "error", message: "La personalización de notificaciones está deshabilitada por el administrador" });
    }
    const update = Object.fromEntries(notificationPreferenceFields.filter((field) => typeof req.body[field] === "boolean").map((field) => [field, req.body[field]]));
    const preferences = await NotificationPreference.findOneAndUpdate({ user_id: req.userId }, { $set: update, $setOnInsert: { user_id: req.userId } }, { returnDocument: "after", upsert: true, setDefaultsOnInsert: true });
    return res.json({ status: "success", message: "Preferencias de notificación actualizadas", preferences });
  } catch {
    return res.status(400).json({ status: "error", message: "No fue posible actualizar las preferencias" });
  }
});

const generateSlaNotificationsForUser = async (userId, preferences) => {
  const now = new Date();
  const involved = { $or: [{ solicitante_id: userId }, { tecnico_id: userId }, { supervisor_id: userId }] };
  const open = { estado: { $nin: ["resuelto", "cerrado"] } };
  const [solicitudes, tickets] = await Promise.all([
    Solicitud.find({ ...involved, ...open, sla_resolution_due: { $ne: null } }).select("folio sla_response_due sla_resolution_due sla_warning_at first_response_at").lean(),
    Ticket.find({ ...involved, ...open, sla_resolution_due: { $ne: null } }).select("folio sla_response_due sla_resolution_due sla_warning_at first_response_at").lean(),
  ]);
  const operations = [];
  for (const [entityType, rows] of [["solicitud", solicitudes], ["ticket", tickets]]) {
    for (const row of rows) {
      const alerts = [];
      if (!row.first_response_at && row.sla_response_due && now >= row.sla_response_due) alerts.push(["sla_breach", "Tiempo de respuesta SLA vencido", `La primera respuesta de ${entityType} ${row.folio} excedió el SLA.`, "response"]);
      if (row.sla_resolution_due && now >= row.sla_resolution_due) alerts.push(["sla_breach", "SLA de resolución vencido", `${entityType === "ticket" ? "El ticket" : "La solicitud"} ${row.folio} excedió el tiempo de resolución.`, "resolution"]);
      else if (row.sla_warning_at && now >= row.sla_warning_at) alerts.push(["sla_warning", "SLA próximo a vencer", `${entityType === "ticket" ? "El ticket" : "La solicitud"} ${row.folio} está próximo a vencer.`, "warning"]);
      for (const [type, title, message, stage] of alerts) {
        if (preferences[type] === false) continue;
        const uniqueKey = `sla:${entityType}:${row._id}:${userId}:${stage}`;
        operations.push({ updateOne: { filter: { unique_key: uniqueKey }, update: { $setOnInsert: { recipient: userId, type, title, message, entity_type: entityType, entity_id: row._id, unique_key: uniqueKey } }, upsert: true } });
      }
    }
  }
  if (operations.length) await Notificacion.bulkWrite(operations, { ordered: false });
};

app.get("/api/notifications", authenticate, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 50);
    const [preferences, globalSettings] = await Promise.all([
      getNotificationPreferences(req.userId),
      getGlobalNotificationSettings(),
    ]);
    await cleanExpiredNotifications(globalSettings.retention_days);
    const effectivePreferences = Object.fromEntries(notificationPreferenceFields.map((field) => [
      field,
      globalSettings.events?.[field] !== false && (!globalSettings.allow_user_preferences || preferences[field] !== false),
    ]));
    await generateSlaNotificationsForUser(req.userId, effectivePreferences);
    const enabledTypes = notificationPreferenceFields.filter((field) => effectivePreferences[field]);
    const [notifications, unreadCount] = await Promise.all([
      Notificacion.find({ recipient: req.userId, type: { $in: enabledTypes } })
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean(),
      Notificacion.countDocuments({ recipient: req.userId, type: { $in: enabledTypes }, read_at: null }),
    ]);
    res.json({
      status: "success", notifications, unreadCount,
      notificationSettings: {
        polling_seconds: globalSettings.polling_seconds,
        allow_user_preferences: globalSettings.allow_user_preferences,
      },
    });
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
      { returnDocument: "after" },
    );
    if (!notification) return notFound(res, "Notificación");
    res.json({ status: "success", notification });
  } catch (error) {
    res.status(400).json({ status: "error", message: "No fue posible actualizar la notificación" });
  }
});

app.get("/api/audit", authenticate, auditViewer, async (req, res) => {
  try {
    const page = Math.max(0, Number.parseInt(req.query.page, 10) || 0);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 20));
    const filter = {};
    if (["acceso", "operacion", "seguridad"].includes(req.query.category)) filter.category = req.query.category;
    if (["true", "false"].includes(req.query.success)) filter.success = req.query.success === "true";
    if (mongoose.isValidObjectId(req.query.user_id)) filter.user_id = req.query.user_id;
    const occurredAt = {};
    if (req.query.from && !Number.isNaN(Date.parse(req.query.from))) occurredAt.$gte = new Date(req.query.from);
    if (req.query.to && !Number.isNaN(Date.parse(req.query.to))) {
      const end = new Date(req.query.to);
      end.setHours(23, 59, 59, 999);
      occurredAt.$lte = end;
    }
    if (Object.keys(occurredAt).length) filter.occurred_at = occurredAt;
    const search = String(req.query.search || "").trim().slice(0, 100);
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escaped, "i");
      filter.$or = ["action", "user_email", "path", "resource", "ip"].map((field) => ({ [field]: regex }));
    }

    const [logs, total] = await Promise.all([
      Auditoria.find(filter)
        .populate("user_id", "username name last_name email")
        .sort({ occurred_at: -1 })
        .skip(page * limit)
        .limit(limit)
        .lean(),
      Auditoria.countDocuments(filter),
    ]);
    return res.json({ status: "success", logs, total });
  } catch (error) {
    console.error("No fue posible consultar la auditoría:", error);
    return res.status(500).json({ status: "error", message: "No fue posible consultar la auditoría" });
  }
});

app.post("/api/logout", (req, res) => {
  let session = {};
  try {
    session = req.cookies.token ? jwt.verify(req.cookies.token, JWT_SECRET) : {};
  } catch {
    session = {};
  }
  res.clearCookie("token", cookieOptions);
  auditAccess(req, { action: "cierre_sesion", user_id: session.userId || null, user_email: normalizeEmail(session.email), success: true, status_code: 200 });
    res
      .status(200)
      .json({ status: "success", message: "Cierre de sesión exitoso" });
});

const PORT = process.env.PORT || 5000;
const startServer = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("✅ Conectado a MongoDB");
    await ensureDefaultCatalogs();
    await ensureRolePermissions();
    await bootstrapInitialAdmin();
    app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
  } catch (error) {
    console.error("❌ No fue posible iniciar la API:", error?.message || error);
    process.exit(1);
  }
};

startServer();
