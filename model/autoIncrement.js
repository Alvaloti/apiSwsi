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
    ]);

    const counter = await Counter.findOneAndUpdate(
      { _id: counterName },
      [
        {
          $set: {
            sequence: {
              $add: [{ $ifNull: ["$sequence", result?.maxValue ?? 0] }, 1],
            },
          },
        },
      ],
      { new: true, upsert: true, updatePipeline: true },
    );

    this[field] = counter.sequence;
  });
}
