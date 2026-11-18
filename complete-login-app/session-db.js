"use strict";

const { DatabaseSync } = require("node:sqlite");

// connect-sqlite3 accepts a driver with the callbacks used by node-sqlite3.
// Keep its session schema and expiry logic while using the SQLite built into Node.
module.exports = function openSessionDatabase(filename) {
  const db = new DatabaseSync(filename);
  db.exec("PRAGMA busy_timeout = 5000");

  function deliver(operation, callback) {
    let result;
    try {
      result = operation();
    } catch (error) {
      if (callback) process.nextTick(callback, error);
      else console.error("Session database cleanup failed", error.code);
      return;
    }
    if (callback) process.nextTick(callback, null, result);
  }

  function statement(method) {
    return (sql, parameters, callback) => {
      if (typeof parameters === "function") {
        callback = parameters;
        parameters = [];
      }
      deliver(() => db.prepare(sql)[method](...(parameters || [])), callback);
    };
  }

  return {
    exec(sql, callback) {
      deliver(() => db.exec(sql), callback);
    },
    run: statement("run"),
    get: statement("get"),
    all: statement("all")
  };
};
