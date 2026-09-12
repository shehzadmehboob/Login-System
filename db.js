require("dotenv").config();

const sql = require("mssql/msnodesqlv8");

const config = {
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        trustedConnection: process.env.DB_TRUSTED_CONNECTION === "true",
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === "true"
    }
};

const poolPromise = sql.connect(config);

module.exports = {
    sql,
    poolPromise
};