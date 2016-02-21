/**
 * @file   keyBank.h
 * @author Jonathan Bedard
 * @date   2/20/2016
 * @brief  Header for the AVL tree based key bank
 * @bug No known bugs.
 *
 * This file contians declarations for the
 * crypto::avlKeyBank and supporting classes.
 * Note that the key-bank may later be
 * implimented with more advanced datastructures.
 *
 */

#ifndef KEY_BANK_H
#define KEY_BANK_H
    
#include "binaryEncryption.h"
#include "cryptoLogging.h"
#include "cryptoError.h"

#include "streamPackage.h"
#include "publicKeyPackage.h"

namespace crypto {
  
    ///@cond INTERNAL
        class nodeNameReference;
        class nodeKeyReference;
        class keyBank;
    ///@endcond
    
    /** @brief Node group
     *
     * A list of all names and
     * keys which are associated with
     * a single node.  This must exist
     * because nodes can change their
     * name during operation.
     */
    class nodeGroup: public os::ptrComp
    {
        /** @brief Pointer to key bank
         */
        keyBank* _master;
        /** @brief List of all names associated with this node
         */
        os::asyncAVLTree<nodeNameReference> nameList;
        /** @brief List of all keys associated with this node
         */
        os::asyncAVLTree<nodeKeyReference> keyList;
		/** @brief Lock used for sorting
	     */
		std::mutex sortingLock;

		/** @brief Array of names sorted by timestamp
		*/
		os::smart_ptr<os::smart_ptr<nodeNameReference> > sortedNames;
		/** @brief Array of keys sorted by timestamp
		*/
		os::smart_ptr<os::smart_ptr<nodeKeyReference> > sortedKeys;

		/**@brief Sorts keys by timestamp
		 */
		void sortKeys();
		/**@brief Sorts names by timestamp
		 */
		void sortNames();
    public:
        /** @brief Node group constructor
         *
         * @param [in/out] master Reference to the 'master' group holder
         * @param [in] groupName Group name of the node being registered
         * @param [in] name Name of the node being registered
         * @param [in] key The public key of a given node
         * @param [in] algoID The algorithm identifier
         * @param [in] keySize Size of the key provided
         */
        nodeGroup(keyBank* master,std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeGroup(){}
        
		/** @brief Allows access to the most recent name
		 *
		 * @param [out] groupName crypto::nodeGroup::sortedNames[0]->groupName()
		 * @param [out] name crypto::nodeGroup::sortedNames[0]->name()
		 * @return void
		 */
		void getName(std::string& groupName,std::string& name);
		/** @brief Concatenated name
		 *
		 * Concatenated the groupName and name
		 * and then returns the combination.
		 *
		 * return groupName+":"+name
		 */
		std::string name();

        /** @brief Returns first name in the list
         *
         * This function returns an alphabetical
         * order.  Note that it is often the case
         * that a user needs to sort by timestamp.
         * This functionality is also provided.
         *
         * @return crypto::nodeGroup::nameList.getFirst()
         */
        os::smart_ptr<os::adnode<nodeNameReference> > getFirstName() {return nameList.getFirst();}
        /** @brief Returns first key in the list
        *
        * This function returns an alphabetical
        * order.  Note that it is often the case
        * that a user needs to sort by timestamp.
        * This functionality is also provided.
        *
        * @return crypto::nodeGroup::keyList.getFirst()
        */
        os::smart_ptr<os::adnode<nodeKeyReference> > getFirstKey() {return keyList.getFirst();}

		/**@brief Merge a node group into this
		 *
		 * Acheives merge entirely by reference.
		 * It is assumed that the node being
		 * merged into this node will shortly be
		 * deleted.
		 *
		 * @param [in] source Node group to merge
		 * @return void
		 */
		void merge(nodeGroup& source);
		/**@brief Add new alias for group
		 *
		 * @param [in] groupName Group name of the node being registered
         * @param [in] name Name of the node being registered
         * @param timestamp The time this node was created, 'now' by defult
		 * @return void
		 */
		void addAlias(std::string groupName,std::string name,uint64_t timestamp=os::getTimestamp());
		/**@brief Add new key for group
		 *
		 * @param [in] key The public key of a given node
         * @param [in] algoID The algorithm identifier
         * @param [in] keySize Size of the key provided
         * @param timestamp The time this node was created, 'now' by defult
		 * @return void
		 */
		void addKey(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp=os::getTimestamp());

		/** @brief Returns the number of names
		 *
		 * @return crypto::nodeGroup::nameList.size()
		 */
		unsigned int numberOfNames() const {return nameList.size();}
		/** @brief Returns the number of keys
		 *
		 * @return crypto::nodeGroup::keyList.size()
		 */
		unsigned int numberOfKeys() const {return keyList.size();}

		/** @brief Returns names sorted by timestamp
		 * @return crypto::nodeGroup::sortedNames
		 */
		os::smart_ptr<os::smart_ptr<nodeNameReference> > namesByTimestamp();
		/** @brief Returns keys sorted by timestamp
		 * @return crypto::nodeGroup::sortedKeys
		 */
		os::smart_ptr<os::smart_ptr<nodeKeyReference> > keysByTimestamp();
        
        /** @brief Build XML tree
         *
         * Builds an XML tree from this node group.
         * This tree is designed to be saved by the
         * key bank.
         *
         * @return Root of tree to be saved
         */
        os::smartXMLNode buildXML();
    };
    
    /** @brief Name storage node
     *
     * Allows for storage and sorting of
     * a node group by its name.  This node
     * holds a reference to the larger group
     * node.
     */
    class nodeNameReference
    {
        /** @brief Friendship with crypto::nodeGroup
         *
         * Only node groupings can meaningfully create
         * this class, so the constructor is private
         * and only accessable by crypto::nodeGroup.
         */
        friend class nodeGroup;
        /** @brief Friendship with crypto::keyBank
         *
         * The key bank must be able to create
         * a node name to search by name
         */
        friend class keyBank;
        
        /** @brief Pointer to node group
         */
        nodeGroup* _master;
        /** @brief Name of the group this name is from
         */
        std::string _groupName;
        /** @brief Name of the node
         */
        std::string _name;
        /** @brief Timestamp key created
         */
        uint64_t _timestamp;
    
        /** @brief Name reference node constructor
         *
         * @param [in/out] master Reference to the 'master' group
         * @param [in] groupName Group name of the node being registered
         * @param [in] name Name of the node being registered
         * @param timestamp The time this node was created, 'now' by defult
         */
        nodeNameReference(nodeGroup* master,std::string groupName,std::string name,uint64_t timestamp=os::getTimestamp());
        /** @brief Name reference node constructor for searching
         *
         * @param [in] groupName Group name of the node being registered
         * @param [in] name Name of the node being registered
         */
        nodeNameReference(std::string groupName,std::string name);
    public:
		 
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeNameReference(){}
        
        /** @brief Returns a pointer to its master
         * @return crypto::nodeNameReference::_master
         */
        nodeGroup* master() {return _master;}
        /** @brief Returns the group name
         * @return crypto::nodeNameReference::_groupName
         */
        std::string groupName() const {return _groupName;}
        /** @brief Returns the name
         * @return crypto::nodeNameReference::_name
         */
        std::string name() const {return _name;}
        /** @brief Returns the timestamp
         * @return crypto::nodeNameReference::_timestamp
         */
        uint64_t timestamp() const {return _timestamp;}
        
        /** @brief Compare crypto::nodeNameReference
         *
         * Compares two node name references by their
         * group and name, returning the result in the
         * form of a 1,0 or -1.
         *
         * @param [in] comp Name reference to compare against
         * @return 1, 0, -1 (Greater than, equal to, less than)
         */
        int compare(const nodeNameReference& comp)const;
        
        /** @brief Equality operator
         *
         * @param [in] comp Name reference to compare against
         * @return true if equal, else, false
         */
        bool operator==(const nodeNameReference& comp) const{return compare(comp)==0;}
        /** @brief Not-equals operator
         *
         * @param [in] comp Name reference to compare against
         * @return true if not equal, else, false
         */
        bool operator!=(const nodeNameReference& comp) const{return compare(comp)!=0;}
        /** @brief Greater-than operator
         *
         * @param [in] comp Name reference to compare against
         * @return true if greater than, else, false
         */
        bool operator>(const nodeNameReference& comp) const{return compare(comp)==1;}
        /** @brief Greater-than/equals to operator
         *
         * @param [in] comp Name reference to compare against
         * @return true if greater than or equal to, else, false
         */
        bool operator>=(const nodeNameReference& comp) const{return compare(comp)!=-1;}
        /** @brief Less-than operator
         *
         * @param [in] comp Name reference to compare against
         * @return true if less than, else, false
         */
        bool operator<(const nodeNameReference& comp) const{return compare(comp)==-1;}
        /** @brief Less-than/equals to operator
         *
         * @param [in] comp Name reference to compare against
         * @return true if less than or equal to, else, false
         */
        bool operator<=(const nodeNameReference& comp) const{return compare(comp)!=1;}
    };
    
    /** @brief Key storage node
     *
     * Allows for storage and sorting of
     * a node group by its key.  This node
     * holds a reference to the larger group
     * node.
     */
    class nodeKeyReference
    {
        /** @brief Friendship with crypto::nodeGroup
         *
         * Only node groupings can meaningfully create
         * this class, so the constructor is private
         * and only accessable by crypto::nodeGroup.
         */
        friend class nodeGroup;
        /** @brief Friendship with crypto::keyBank
         *
         * The key bank must be able to create
         * a node key to search by key
         */
        friend class keyBank;
        
        /** @brief Pointer to node group
         */
        nodeGroup* _master;
        /** @brief Shared pointer to public key
         */
        os::smart_ptr<number> _key;
        /** @brief ID of public key algorithm
         */
        uint16_t _algoID;
        /** @brief Size of public key
         */
        uint16_t _keySize;
        /** @brief Timestamp key created
         */
        uint64_t _timestamp;
    
        /** @brief Key reference node constructor
        *
        * @param [in/out] master Reference to the 'master' group
        * @param [in] key The public key of a given node
        * @param [in] algoID The algorithm identifier
        * @param [in] keySize Size of the key provided
        * @param timestamp The time this node was created, 'now' by defult
        */
        nodeKeyReference(nodeGroup* master,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp=os::getTimestamp());
        /** @brief Key reference node constructor for searching
         *
         * @param [in] key The public key of a given node
         * @param [in] algoID The algorithm identifier
         * @param [in] keySize Size of the key provided
         */
        nodeKeyReference(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize);
    public:
		
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeKeyReference(){}
        
        /** @brief Returns a pointer to its master
         * @return crypto::~nodeKeyReference::_master
         */
        nodeGroup* master() {return _master;}
        /** @brief Returns the key
         * @return crypto::nodeKeyReference::_key
         */
        os::smart_ptr<number> key() const {return _key;}
        /** @brief Returns the algorithm key
         * @return crypto::nodeKeyReference::_algoID
         */
        uint16_t algoID() const {return _algoID;}
        /** @brief Returns the key size
         * @return crypto::nodeKeyReference::_keySize
         */
        uint16_t keySize() const {return _keySize;}
        /** @brief Returns the timestamp
         * @return crypto::nodeKeyReference::_timestamp
         */
        uint64_t timestamp() const {return _timestamp;}
        
        /** @brief Compare crypto::nodeKeyReference
         *
         * Compares two node key references by their
         * public key, returning the result in the
         * form of a 1,0 or -1.
         *
         * @param [in] comp Key reference to compare against
         * @return 1, 0, -1 (Greater than, equal to, less than)
         */
        int compare(const nodeKeyReference& comp)const;
        
        /** @brief Equality operator
         *
         * @param [in] comp Key reference to compare against
         * @return true if equal, else, false
         */
        bool operator==(const nodeKeyReference& comp) const{return compare(comp)==0;}
        /** @brief Not-equals operator
         *
         * @param [in] comp Key reference to compare against
         * @return true if not equal, else, false
         */
        bool operator!=(const nodeKeyReference& comp) const{return compare(comp)!=0;}
        /** @brief Greater-than operator
         *
         * @param [in] comp Key reference to compare against
         * @return true if greater than, else, false
         */
        bool operator>(const nodeKeyReference& comp) const{return compare(comp)==1;}
        /** @brief Greater-than/equals to operator
         *
         * @param [in] comp Key reference to compare against
         * @return true if greater than or equal to, else, false
         */
        bool operator>=(const nodeKeyReference& comp) const{return compare(comp)!=-1;}
        /** @brief Less-than operator
         *
         * @param [in] comp Key reference to compare against
         * @return true if less than, else, false
         */
        bool operator<(const nodeKeyReference& comp) const{return compare(comp)==-1;}
        /** @brief Less-than/equals to operator
         *
         * @param [in] comp Key reference to compare against
         * @return true if less than or equal to, else, false
         */
        bool operator<=(const nodeKeyReference& comp) const{return compare(comp)!=1;}
    };
    
    
    /** @brief Key bank interface
     *
     * Acts as an interface for classes
     * which allow for the storing, saving
     * and searching of cyptographic keys.
     * These banks act, in essense, as
     * data-bases.
     */
    class keyBank
    {
        /** @brief Path to save file
         */
        std::string _savePath;
        
        /** @brief Friendship with node grouping
         *
         * Node groups must be able to push
         * name and key nodes onto the key bank.
         */
        friend class nodeGroup;
    protected:
        /** @brief Add name node
         *
         * Inserts a name node into
         * the bank.  The name node
         * has a reference to a
         * node group.
         *
         * @param [in] name Name node to be added
         * @return void
         */
		virtual void pushNewNode(os::smart_ptr<nodeNameReference> name)=0;
        /** @brief Add key node
         *
         * Inserts a key node into
         * the bank.  The key node
         * has a reference to a
         * node group.
         *
         * @param [in] key Key node to be added
         * @return void
         */
		virtual void pushNewNode(os::smart_ptr<nodeKeyReference> key)=0;
        /** @brief Loads bank from file
         * @return void
         */
		virtual void load()=0;
    
        /** @brief Construct with save path
         *
         * @param [in] savePath Path to save file
         */
        keyBank(std::string savePath){_savePath=savePath;}
    public:
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~keyBank(){}
        /** @brief Adds authenticated node to bank
         *
         * Note that if a node has not be authenticated,
         * adding it to the bank will cause a potential
         * security vulnerability.  Nodes should be authenticated
         * before being added to the bank.
         *
         * @param [in] groupName Name of the node's group
         * @param [in] name Name of the node
         * @param [in] key Key of node to be added
         * @param [in] algoID ID of algorithm for key
         * @param [in] keySize Length of key of the node
         * @return Return reference to the new node group
         */
        virtual os::smart_ptr<nodeGroup> addPair(std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)=0;

        /** @brief Saves bank to file
         * @return void
         */
		virtual void save()=0;
        /** @brief Get save path
         * @return crypto::keyBank::_savePath
         */
		std::string& savePath() const {_savePath;}
        
        /** @brief Find by group name reference
         *
         * @param [in] name Name reference to be searched
         * @return Node group found by arguments
         */
        virtual os::smart_ptr<nodeGroup> find(os::smart_ptr<nodeNameReference> name)=0;
        /** @brief Find by group key reference
         *
         * @param [in] key Key reference to be searched
         * @return Node group found by arguments
         */
        virtual os::smart_ptr<nodeGroup> find(os::smart_ptr<nodeKeyReference> key)=0;
        /** @brief Find by group name and name
         *
         * @param [in] groupName Name of the node's group
         * @param [in] name Name of the node
         * @return Node group found by arguments
         */
        virtual os::smart_ptr<nodeGroup> find(std::string groupName,std::string name)
        {return find(os::smart_ptr<nodeNameReference>(new nodeNameReference(groupName,name),os::shared_type));}
        /** @brief Find by key information
         *
         * @param [in] key Key of node to be added
         * @param [in] algoID ID of algorithm for key
         * @param [in] keySize Length of key of the node
         * @return Node group found by arguments
         */
        virtual os::smart_ptr<nodeGroup> find(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
        {return find(os::smart_ptr<nodeKeyReference>(new nodeKeyReference(key,algoID,keySize),os::shared_type));}
    };
    /** @brief AVL key back
     *
     * The AVL key bank stores keys in
     * a series of AVL trees.  All keys
     * in the bank are loaded into memory
     * when the file is loaded, meaning
     * that there is a limited number
     * of keys that can be practically
     * managed through an AVL key bank.
     */
    class avlKeyBank: public keyBank
    {
        /** @brief List of all names associated with this node
         */
        os::asyncAVLTree<nodeNameReference> nameTree;
        /** @brief List of all keys associated with this node
         */
        os::asyncAVLTree<nodeKeyReference> keyTree;
        /** @brief List of all node groups
         */
        os::asyncAVLTree<nodeGroup> nodeBank;
    protected:
        /** @brief Add name node
         *
         * Inserts a name node into
         * the bank.  The name node
         * has a reference to a
         * node group.
         *
         * @param [in] name Name node to be added
         * @return void
         */
        void pushNewNode(os::smart_ptr<nodeNameReference> name);
        /** @brief Add key node
         *
         * Inserts a key node into
         * the bank.  The key node
         * has a reference to a
         * node group.
         *
         * @param [in] key Key node to be added
         * @return void
         */
        void pushNewNode(os::smart_ptr<nodeKeyReference> key);
        /** @brief Loads bank from file
         * @return void
         */
        void load();
    public:
        /** @brief Construct with save path
         *
         * Intializes the key bank and
         * loads the the bank from a file.
         *
         * @param [in] savePath Path to save file
         */
        avlKeyBank(std::string savePath);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~avlKeyBank(){}
        
        /** @brief Saves bank to file
         * @return void
         */
        void save();
        
        /** @brief Adds authenticated node to bank
         *
         * Note that if a node has not be authenticated,
         * adding it to the bank will cause a potential
         * security vulnerability.  Nodes should be authenticated
         * before being added to the bank.
         *
         * @param [in] groupName Name of the node's group
         * @param [in] name Name of the node
         * @param [in] key Key of node to be added
         * @param [in] algoID ID of algorithm for key
         * @param [in] keySize Length of key of the node
         * @return Return reference to the new node group
         */
        os::smart_ptr<nodeGroup> addPair(std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize);
        /** @brief Find by group name reference
         *
         * @param [in] name Name reference to be searched
         * @return Node group found by arguments
         */
        os::smart_ptr<nodeGroup> find(os::smart_ptr<nodeNameReference> name);
        /** @brief Find by group key reference
         *
         * @param [in] key Key reference to be searched
         * @return Node group found by arguments
         */
        os::smart_ptr<nodeGroup> find(os::smart_ptr<nodeKeyReference> key);
        /** @brief Find by group name and name
         *
         * @param [in] groupName Name of the node's group
         * @param [in] name Name of the node
         * @return Node group found by arguments
         */
        inline os::smart_ptr<nodeGroup> find(std::string groupName,std::string name)
        {return keyBank::find(groupName,name);}
        /** @brief Find by key information
         *
         * @param [in] key Key of node to be added
         * @param [in] algoID ID of algorithm for key
         * @param [in] keySize Length of key of the node
         * @return Node group found by arguments
         */
        inline os::smart_ptr<nodeGroup> find(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
        {return keyBank::find(key,algoID,keySize);}
    };

}

#endif
