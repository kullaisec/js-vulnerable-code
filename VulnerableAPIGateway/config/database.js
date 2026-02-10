/**
 * Database Configuration and Query Builder
 * Contains vulnerable query construction patterns
 */

const mysql = require('mysql2/promise');
const { MongoClient } = require('mongodb');

class DatabaseConfig {
    constructor() {
        this.mysqlPool = null;
        this.mongoClient = null;
    }

    async getMySQLConnection() {
        if (!this.mysqlPool) {
            this.mysqlPool = mysql.createPool({
                host: process.env.DB_HOST || 'localhost',
                user: process.env.DB_USER || 'root',
                password: process.env.DB_PASS || 'password',
                database: process.env.DB_NAME || 'apigateway',
                waitForConnections: true,
                connectionLimit: 10
            });
        }
        return this.mysqlPool;
    }

    async getMongoConnection() {
        if (!this.mongoClient) {
            const uri = process.env.MONGO_URI || 'mongodb://localhost:27017';
            this.mongoClient = new MongoClient(uri);
            await this.mongoClient.connect();
        }
        return this.mongoClient.db('apigateway');
    }
}

/**
 * VULNERABLE: Query builder with SQL injection
 * This is a custom sink that accepts tainted data
 */
class QueryBuilder {
    constructor(connection) {
        this.connection = connection;
    }

    // SINK: SQL Injection - Direct string concatenation
    async findByField(table, field, value) {
        const query = `SELECT * FROM ${table} WHERE ${field} = '${value}'`;
        const [rows] = await this.connection.execute(query);
        return rows;
    }

    // SINK: SQL Injection - Dynamic ORDER BY
    async findAllOrdered(table, orderField, orderDir) {
        const query = `SELECT * FROM ${table} ORDER BY ${orderField} ${orderDir}`;
        const [rows] = await this.connection.execute(query);
        return rows;
    }

    // SINK: SQL Injection - IN clause construction
    async findByIds(table, ids) {
        const idList = ids.join(',');
        const query = `SELECT * FROM ${table} WHERE id IN (${idList})`;
        const [rows] = await this.connection.execute(query);
        return rows;
    }

    // SINK: SQL Injection - LIKE clause
    async searchByPattern(table, field, pattern) {
        const query = `SELECT * FROM ${table} WHERE ${field} LIKE '%${pattern}%'`;
        const [rows] = await this.connection.execute(query);
        return rows;
    }

    // SINK: SQL Injection - Dynamic table name
    async dynamicQuery(tableName, conditions) {
        let query = `SELECT * FROM ${tableName} WHERE 1=1`;
        for (const [key, value] of Object.entries(conditions)) {
            query += ` AND ${key} = '${value}'`;
        }
        const [rows] = await this.connection.execute(query);
        return rows;
    }

    // SINK: NoSQL Injection - MongoDB $where
    async mongoFindWhere(collection, whereClause) {
        return await collection.find({ $where: whereClause }).toArray();
    }

    // SINK: NoSQL Injection - Unvalidated query object
    async mongoFind(collection, queryObj) {
        return await collection.find(queryObj).toArray();
    }
}

/**
 * CUSTOM SINK: Audit logger that writes to database
 * Vulnerable to second-order SQL injection
 */
class AuditLogger {
    constructor(connection) {
        this.connection = connection;
    }

    // SINK: Second-order SQL injection through logging
    async logAction(userId, action, details) {
        const query = `INSERT INTO audit_log (user_id, action, details, timestamp)
                       VALUES ('${userId}', '${action}', '${details}', NOW())`;
        await this.connection.execute(query);
    }

    // SINK: Stored data used in subsequent query
    async getLogsForUser(userId) {
        // First query - stores tainted data
        const query = `SELECT details FROM audit_log WHERE user_id = '${userId}'`;
        const [rows] = await this.connection.execute(query);
        return rows;
    }
}

module.exports = {
    DatabaseConfig,
    QueryBuilder,
    AuditLogger
};
