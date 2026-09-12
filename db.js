require("dotenv").config();

const sql = require("mssql/msnodesqlv8");

const config = {
    connectionString: process.env.DB_CONNECTION_STRING
};

const poolPromise = sql.connect(config);

module.exports = {
    sql,
    poolPromise
};