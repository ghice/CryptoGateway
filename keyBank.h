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
    class nodeGroup: os::ptrComp
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
    
    public:
		 /** @brief Name reference node constructor for searching
         *
         * @param [in] groupName Group name of the node being registered
         * @param [in] name Name of the node being registered
         */
		nodeNameReference(std::string groupName,std::string name);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeNameReference(){}
        
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
    public:
		/** @brief Key reference node constructor for searching
        *
        * @param [in] key The public key of a given node
        * @param [in] algoID The algorithm identifier
        * @param [in] keySize Size of the key provided
        */
        nodeKeyReference(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeKeyReference(){}
        
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
        std::string _savePath;
    protected:
		friend class nodeGroup;

		virtual void pushNewNode(os::smart_ptr<nodeNameReference> name)=0;
		virtual void pushNewNode(os::smart_ptr<nodeKeyReference> key)=0;
		virtual void load()=0;
    public:
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~keyBank(){}
        virtual os::smart_ptr<nodeGroup> addPair(std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)=0;

		virtual void save()=0;
		std::string savePath() const {_savePath;}
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
    class avlKeyBank
    {
        
    };

}

#endif
