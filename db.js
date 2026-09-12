const sql = require("mssql/msnodesqlv8");

const config = {
    connectionString:
        "Driver={ODBC Driver 18 for SQL Server};" +
        "Server=SHAGGY\\SQLEXPRESS;" +
        "Database=LoginSystem;" +
        "Trusted_Connection=Yes;" +
        "TrustServerCertificate=Yes;"
};

const poolPromise = sql.connect(config);

module.exports = {
    sql,
    poolPromise
};