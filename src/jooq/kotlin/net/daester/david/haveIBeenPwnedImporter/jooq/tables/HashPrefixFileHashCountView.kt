/*
 * This file is generated by jOOQ.
 */
package net.daester.david.haveIBeenPwnedImporter.jooq.tables


import kotlin.collections.Collection

import net.daester.david.haveIBeenPwnedImporter.jooq.Pwned
import net.daester.david.haveIBeenPwnedImporter.jooq.tables.records.HashPrefixFileHashCountViewRecord

import org.jooq.Condition
import org.jooq.Field
import org.jooq.ForeignKey
import org.jooq.InverseForeignKey
import org.jooq.Name
import org.jooq.PlainSQL
import org.jooq.QueryPart
import org.jooq.Record
import org.jooq.SQL
import org.jooq.Schema
import org.jooq.Select
import org.jooq.Stringly
import org.jooq.Table
import org.jooq.TableField
import org.jooq.TableOptions
import org.jooq.impl.DSL
import org.jooq.impl.SQLDataType
import org.jooq.impl.TableImpl


/**
 * This class is generated by jOOQ.
 */
@Suppress("UNCHECKED_CAST")
open class HashPrefixFileHashCountView(
    alias: Name,
    path: Table<out Record>?,
    childPath: ForeignKey<out Record, HashPrefixFileHashCountViewRecord>?,
    parentPath: InverseForeignKey<out Record, HashPrefixFileHashCountViewRecord>?,
    aliased: Table<HashPrefixFileHashCountViewRecord>?,
    parameters: Array<Field<*>?>?,
    where: Condition?
): TableImpl<HashPrefixFileHashCountViewRecord>(
    alias,
    Pwned.PWNED,
    path,
    childPath,
    parentPath,
    aliased,
    parameters,
    DSL.comment(""),
    TableOptions.view("create view `hash_prefix_file_hash_count_view` as select `pwned`.`hash`.`hash_prefix` AS `hash_prefix`,`pwned`.`hash`.`file_hash` AS `file_hash`,count(0) AS `hashes` from `pwned`.`hash` group by `pwned`.`hash`.`hash_prefix`,`pwned`.`hash`.`file_hash`"),
    where,
) {
    companion object {

        /**
         * The reference instance of
         * <code>pwned.hash_prefix_file_hash_count_view</code>
         */
        val HASH_PREFIX_FILE_HASH_COUNT_VIEW: HashPrefixFileHashCountView = HashPrefixFileHashCountView()
    }

    /**
     * The class holding records for this type
     */
    override fun getRecordType(): Class<HashPrefixFileHashCountViewRecord> = HashPrefixFileHashCountViewRecord::class.java

    /**
     * The column
     * <code>pwned.hash_prefix_file_hash_count_view.hash_prefix</code>.
     */
    val HASH_PREFIX: TableField<HashPrefixFileHashCountViewRecord, String?> = createField(DSL.name("hash_prefix"), SQLDataType.CHAR(5).nullable(false), this, "")

    /**
     * The column <code>pwned.hash_prefix_file_hash_count_view.file_hash</code>.
     */
    val FILE_HASH: TableField<HashPrefixFileHashCountViewRecord, String?> = createField(DSL.name("file_hash"), SQLDataType.VARCHAR(255).nullable(false), this, "")

    /**
     * The column <code>pwned.hash_prefix_file_hash_count_view.hashes</code>.
     */
    val HASHES: TableField<HashPrefixFileHashCountViewRecord, Long?> = createField(DSL.name("hashes"), SQLDataType.BIGINT.nullable(false).defaultValue(DSL.field(DSL.raw("0"), SQLDataType.BIGINT)), this, "")

    private constructor(alias: Name, aliased: Table<HashPrefixFileHashCountViewRecord>?): this(alias, null, null, null, aliased, null, null)
    private constructor(alias: Name, aliased: Table<HashPrefixFileHashCountViewRecord>?, parameters: Array<Field<*>?>?): this(alias, null, null, null, aliased, parameters, null)
    private constructor(alias: Name, aliased: Table<HashPrefixFileHashCountViewRecord>?, where: Condition?): this(alias, null, null, null, aliased, null, where)

    /**
     * Create an aliased <code>pwned.hash_prefix_file_hash_count_view</code>
     * table reference
     */
    constructor(alias: String): this(DSL.name(alias))

    /**
     * Create an aliased <code>pwned.hash_prefix_file_hash_count_view</code>
     * table reference
     */
    constructor(alias: Name): this(alias, null)

    /**
     * Create a <code>pwned.hash_prefix_file_hash_count_view</code> table
     * reference
     */
    constructor(): this(DSL.name("hash_prefix_file_hash_count_view"), null)
    override fun getSchema(): Schema? = if (aliased()) null else Pwned.PWNED
    override fun `as`(alias: String): HashPrefixFileHashCountView = HashPrefixFileHashCountView(DSL.name(alias), this)
    override fun `as`(alias: Name): HashPrefixFileHashCountView = HashPrefixFileHashCountView(alias, this)
    override fun `as`(alias: Table<*>): HashPrefixFileHashCountView = HashPrefixFileHashCountView(alias.qualifiedName, this)

    /**
     * Rename this table
     */
    override fun rename(name: String): HashPrefixFileHashCountView = HashPrefixFileHashCountView(DSL.name(name), null)

    /**
     * Rename this table
     */
    override fun rename(name: Name): HashPrefixFileHashCountView = HashPrefixFileHashCountView(name, null)

    /**
     * Rename this table
     */
    override fun rename(name: Table<*>): HashPrefixFileHashCountView = HashPrefixFileHashCountView(name.qualifiedName, null)

    /**
     * Create an inline derived table from this table
     */
    override fun where(condition: Condition?): HashPrefixFileHashCountView = HashPrefixFileHashCountView(qualifiedName, if (aliased()) this else null, condition)

    /**
     * Create an inline derived table from this table
     */
    override fun where(conditions: Collection<Condition>): HashPrefixFileHashCountView = where(DSL.and(conditions))

    /**
     * Create an inline derived table from this table
     */
    override fun where(vararg conditions: Condition?): HashPrefixFileHashCountView = where(DSL.and(*conditions))

    /**
     * Create an inline derived table from this table
     */
    override fun where(condition: Field<Boolean?>?): HashPrefixFileHashCountView = where(DSL.condition(condition))

    /**
     * Create an inline derived table from this table
     */
    @PlainSQL override fun where(condition: SQL): HashPrefixFileHashCountView = where(DSL.condition(condition))

    /**
     * Create an inline derived table from this table
     */
    @PlainSQL override fun where(@Stringly.SQL condition: String): HashPrefixFileHashCountView = where(DSL.condition(condition))

    /**
     * Create an inline derived table from this table
     */
    @PlainSQL override fun where(@Stringly.SQL condition: String, vararg binds: Any?): HashPrefixFileHashCountView = where(DSL.condition(condition, *binds))

    /**
     * Create an inline derived table from this table
     */
    @PlainSQL override fun where(@Stringly.SQL condition: String, vararg parts: QueryPart): HashPrefixFileHashCountView = where(DSL.condition(condition, *parts))

    /**
     * Create an inline derived table from this table
     */
    override fun whereExists(select: Select<*>): HashPrefixFileHashCountView = where(DSL.exists(select))

    /**
     * Create an inline derived table from this table
     */
    override fun whereNotExists(select: Select<*>): HashPrefixFileHashCountView = where(DSL.notExists(select))
}