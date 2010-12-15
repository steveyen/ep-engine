/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <string>
#include <map>

#include "common.hh"
#include "stats.hh"
#include "kvstore.hh"
#include "sqlite-kvstore.hh"

KVStore *KVStore::create(db_type type, EPStats &stats,
                         const KVStoreConfig &conf) {
    SqliteStrategy *sqliteInstance = NULL;
    switch (type) {
    case multi_db:
        sqliteInstance = new MultiDBSingleTableSqliteStrategy(conf.location,
                                                              conf.shardPattern,
                                                              conf.initFile,
                                                              conf.postInitFile,
                                                              conf.shards);
        break;
    case single_db:
        sqliteInstance = new SingleTableSqliteStrategy(conf.location,
                                                       conf.initFile,
                                                       conf.postInitFile);
        break;
    case single_mt_db:
        sqliteInstance = new MultiTableSqliteStrategy(conf.location,
                                                      conf.initFile,
                                                      conf.postInitFile);
        break;
    }
    return new StrategicSqlite3(stats,
                                shared_ptr<SqliteStrategy>(sqliteInstance));
}

static const char* MULTI_DB_NAME("multiDB");
static const char* SINGLE_DB_NAME("singleDB");
static const char* SINGLE_MT_DB_NAME("singleMTDB");

const char* KVStore::typeToString(db_type type) {
    char *rv(NULL);
    switch (type) {
    case multi_db:
        return MULTI_DB_NAME;
        break;
    case single_db:
        return SINGLE_DB_NAME;
        break;
    case single_mt_db:
        return SINGLE_MT_DB_NAME;
        break;
    }
    assert(rv);
    return rv;
}

bool KVStore::stringToType(const char *name,
                           enum db_type &typeOut) {
    bool rv(true);
    if (strcmp(name, MULTI_DB_NAME) == 0) {
        typeOut = multi_db;
    } else if(strcmp(name, SINGLE_DB_NAME) == 0) {
        typeOut = single_db;
    } else if(strcmp(name, SINGLE_MT_DB_NAME) == 0) {
        typeOut = single_mt_db;
    } else {
        rv = false;
    }
    return rv;
}