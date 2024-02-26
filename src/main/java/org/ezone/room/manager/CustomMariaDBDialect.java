package org.ezone.room.manager;

import org.hibernate.dialect.MariaDBDialect;
import org.hibernate.type.BasicTypeRegistry;
import org.hibernate.query.spi.QueryEngine;
import org.hibernate.query.sqm.function.SqmFunctionRegistry;
import org.hibernate.type.StandardBasicTypes;

public class CustomMariaDBDialect extends MariaDBDialect {

    public void initializeFunctionRegistry(QueryEngine queryEngine) {
        BasicTypeRegistry basicTypeRegistry = queryEngine.getTypeConfiguration().getBasicTypeRegistry();
        SqmFunctionRegistry functionRegistry = queryEngine.getSqmFunctionRegistry();
        functionRegistry.registerPattern(
                "bitand",
                "(?1 & ?2)",
                basicTypeRegistry.resolve(StandardBasicTypes.INTEGER)
        );
    }
}