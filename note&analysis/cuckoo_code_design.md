In order to support the keyword functionality by using cuckoo hashing, we need to change both the server side and the client side query. We need to implement both the Lookup and Insertion algorithms. A simple pseudocode can be found in wiki page(https://en.wikipedia.org/wiki/Cuckoo_hashing).

The followings are a list of functions we need to modify. 

- Modify `set_database` to `set_cuckoo_database` in `server.cpp`. This function mainly deal with the Insertion algorithm for cuckoo hashing. The server should try inserting untill it success. All hash functions must be made public. The client can "download" the hash functions that works.
- Modify `generate_query` to `generate_cuckoo_query` in `client.cpp`. Given a keyword to this new function, it first hashes the keyword to two entry indices by using the downloaded hash function. Then use `generate_query` twice to get two encoded queries.
- Another new function on the client side is required for selecting the correct output.