// Bounded Cursor reads. Previews are separate from editable snapshots.
const MAX_ROWS = 100, MAX_COLUMNS = 32, MAX_BYTES = 65536;
function tableBytes(table) {
  let bytes = 0;
  for (const char of JSON.stringify(table)) {
    const code = char.codePointAt(0);
    bytes += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  }
  return bytes;
}
function validateTable(table) {
  if (!table || typeof table !== 'object' || Array.isArray(table) ||
      Object.keys(table).sort().join(',') !== 'columns,rows' ||
      !Array.isArray(table.columns) || !table.columns.length || table.columns.length > MAX_COLUMNS ||
      table.columns.some(x => typeof x !== 'string' || x.length > 256) ||
      new Set(table.columns).size !== table.columns.length ||
      !Array.isArray(table.rows) || table.rows.length > MAX_ROWS || tableBytes(table) > MAX_BYTES)
    throw new Error('Cursor table requires unique columns and at most 100 rows, 32 columns and 64 KiB');
  for (const row of table.rows) {
    if (!Array.isArray(row) || row.length !== table.columns.length) throw new Error('Each row must match the columns');
    for (const cell of row) {
      if (!cell || Object.keys(cell).sort().join(',') !== 'type,value') throw new Error('Cells require type and value');
      const { type, value } = cell;
      if (type === 'null' && value === null) continue;
      if (type === 'string' && typeof value === 'string' && value.length <= 8192) continue;
      if (type === 'float' && typeof value === 'number' && Number.isFinite(value)) continue;
      if (type === 'integer' && typeof value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value) &&
          BigInt(value) >= -9223372036854775808n && BigInt(value) <= 9223372036854775807n) continue;
      throw new Error('Unsupported Cursor cell or out-of-range value');
    }
  }
  return table;
}
function readCell(cursor, column, type = cursor.getType(column)) {
  switch (type) {
    case 0: return { type: 'null', value: null };
    case 1: return { type: 'integer', value: String(cursor.getLong(column)) };
    case 2: return { type: 'float', value: cursor.getDouble(column) };
    case 3: return { type: 'string', value: String(cursor.getString(column)) };
    default: throw new Error('Blob or unsupported Cursor cell; original result kept');
  }
}

function previewCursor(cursor) {
  const position = cursor.getPosition();
  const columns = Array.from(cursor.getColumnNames(), String);
  if (columns.length > MAX_COLUMNS || columns.some(name => name.length > 256))
    throw new Error('Cursor exceeds preview column limits');
  const preview = { columns, rows: [], complete: false, reason: 'Row limit reached' };
  try {
    for (let index = 0; index <= MAX_ROWS; index++) {
      if (!cursor.moveToPosition(index)) {
        if (cursor.getPosition() !== index) throw new Error('Cursor could not reach the next row');
        preview.complete = true;
        delete preview.reason;
        break;
      }
      if (index === MAX_ROWS) break;
      const row = columns.map((_, column) => {
        const type = cursor.getType(column);
        if (type === 4) return { type: 'omitted', value: 'Blob' };
        const cell = readCell(cursor, column, type);
        if (cell.type === 'string' && cell.value.length > 8192)
          return { type: 'omitted', value: 'String exceeds cell limit' };
        if (cell.type === 'float' && !Number.isFinite(cell.value))
          return { type: 'omitted', value: 'Non-finite number' };
        return cell;
      });
      preview.rows.push(row);
      if (tableBytes(preview) > MAX_BYTES) {
        preview.rows.pop();
        preview.reason = 'Size limit reached';
        break;
      }
    }
  } finally {
    if (cursor.getPosition() !== position) cursor.moveToPosition(position);
    if (cursor.getPosition() !== position) throw new Error('Could not restore Cursor position');
  }
  if (preview.complete && preview.rows.some(row => row.some(cell => cell.type === 'omitted'))) {
    preview.complete = false;
    preview.reason = 'Some cell values omitted';
  }
  return preview;
}

function snapshotCursor(cursor) {
  const position = cursor.getPosition();
  let failure = null, table;
  try {
    const count = cursor.getCount(), columns = Array.from(cursor.getColumnNames(), String);
    if (count > MAX_ROWS || columns.length > MAX_COLUMNS) throw new Error('Cursor exceeds snapshot limits (100 rows, 32 columns)');
    table = { columns, rows: [] };
    for (let row = 0; row < count; row++) {
      if (!cursor.moveToPosition(row)) throw new Error('Cursor changed while being read');
      table.rows.push(columns.map((_, col) => readCell(cursor, col)));
      if (tableBytes(table) > MAX_BYTES) throw new Error('Cursor exceeds 64 KiB snapshot limit');
    }
    validateTable(table);
  } catch (error) { failure = error; }
  finally {
    cursor.moveToPosition(position);
    if (cursor.getPosition() !== position) throw new Error('Could not restore Cursor position; replacement disabled');
  }
  if (failure) throw failure;
  return table;
}
function buildCursor(Java, table, javaText) {
  validateTable(table);
  const cursor = Java.use('android.database.MatrixCursor').$new(Java.array('java.lang.String', table.columns.map(javaText)));
  try {
    for (const row of table.rows) {
      const values = row.map(cell => {
        if (cell.type === 'null') return null;
        if (cell.type === 'string') return Java.use('java.lang.String').$new(javaText(cell.value));
        return Java.use(cell.type === 'integer' ? 'java.lang.Long' : 'java.lang.Double').valueOf(String(cell.value));
      });
      cursor.addRow.overload('[Ljava.lang.Object;').call(cursor, Java.array('java.lang.Object', values));
    }
    return cursor;
  } catch (error) { cursor.close(); throw error; }
}
module.exports = { snapshotCursor, previewCursor, validateTable, buildCursor };
