**NoSQL** (Not Only SQL) refers to a category of databases that provide a flexible alternative to traditional relational databases. They are designed to handle large volumes of unstructured, semi-structured, and structured data, making them ideal for modern applications with high scalability and performance requirements.

## Key Characteristics of NoSQL Databases

- **Schema Flexibility:** No fixed schema, allowing dynamic and evolving data structures.
- **Horizontal Scalability:** Designed to scale out by distributing data across multiple servers.
- **High Performance:** Optimized for fast read and write operations.
- **Varied Data Models:** Support for various data representations beyond tables and rows.

## Types of NoSQL Databases

-  **Document Stores:**    
    - Store data as JSON or BSON documents.
    - Examples: MongoDB, Couchbase.
    - Use case: Content management systems, real-time analytics.
```json
{
  "_id": "1",
  "name": "John Doe",
  "email": "john@example.com",
  "orders": [
    { "product": "Laptop", "price": 1200 },
    { "product": "Mouse", "price": 20 }
  ]
}
```
- **Key-Value Stores:**
    - Store data as key-value pairs.
    - Examples: Redis, Amazon DynamoDB.
    - Use case: Caching, session management.
```json
user:1001 → {"name": "Alice", "age": 30}
session:token123 → {"status": "active", "expiry": "2025-01-01"}
```
- **Column-Family Stores:**
    - Store data in column families instead of rows.
    - Examples: Apache Cassandra, HBase.
    - Use case: Time-series data, logging systems.
```ruby
user_profiles
┌───────────────┬────────────┬───────────┐
│ user_id       │ first_name │ last_name │
├───────────────┼────────────┼───────────┤
│ 1             │ John       │ Doe       │
│ 2             │ Alice      │ Smith     │
```
- **Graph Databases:**
    - Store data as nodes and edges, representing relationships.
    - Examples: Neo4j, ArangoDB.
    - Use case: Social networks, recommendation systems.
```ruby
user:1001 → {"name": "Alice", "age": 30}
session:token123 → {"status": "active", "expiry": "2025-01-01"}
```


## MongoDB User Interaction

Basic commands to interact with MongoDB through the shell:

```java
db.help()                    // Help on db methods  
db.mycoll.help()             // Help on collection methods  
sh.help()                    // Sharding helpers  
rs.help()                    // Replica set helpers  
help admin                   // Administrative help  
help connect                 // Help for connecting to a database  
help keys                    // Key shortcuts  
help misc                    // Miscellaneous useful info  
help mr                      // Help for MapReduce  

show dbs                     // Show database names  
show collections             // Show collections in the current database  
show users                   // Show users in the current database  
show profile                 // Show recent system.profile entries with time >= 1ms  
show logs                    // Show available logger names  
show log [name]              // Print the last segment of a log (default: 'global')  

use <db_name>                // Switch to or create a database  
db.foo.find()                // List documents in the "foo" collection  
db.foo.find({ a: 1 })       // Find documents in "foo" where a == 1  
it                           // Iterate over the results of the last query  
DBQuery.shellBatchSize = x   // Set default number of items displayed in the shell  
exit                         // Quit the MongoDB shell  
```