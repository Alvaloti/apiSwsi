import Counter from "./Counter.js";

/**
 * Asigna un consecutivo atómico a un campo antes de validar el documento.
 * Cada counterName mantiene una secuencia independiente.
 */
export default function autoIncrement(schema, { field = "id", counterName }) {
  schema.pre("validate", async function () {
    if (!this.isNew) return;

    const [result] = await this.constructor.aggregate([
      {
        $project: {
          numericValue: {
            $convert: {
              input: `$${field}`,
              to: "long",
              onError: 0,
              onNull: 0,
            },
          },
        },
      },
      { $group: { _id: null, maxValue: { $max: "$numericValue" } } },
    ]).option({ maxTimeMS: 10000 });

    const maxValue = Number(result?.maxValue) || 0;

    // Sincroniza el contador con datos preexistentes y después incrementa de
    // forma atómica. Evita depender de un pipeline de actualización, que puede
    // quedar pendiente con algunas combinaciones de Mongoose y MongoDB.
    await Counter.updateOne(
      { _id: counterName },
      { $max: { sequence: maxValue } },
      { upsert: true },
    ).maxTimeMS(10000);

    const counter = await Counter.findOneAndUpdate(
      { _id: counterName },
      { $inc: { sequence: 1 } },
      { returnDocument: "after" },
    ).maxTimeMS(10000);

    if (!counter) throw new Error(`No fue posible generar el consecutivo ${counterName}`);

    this[field] = counter.sequence;
  });
}
