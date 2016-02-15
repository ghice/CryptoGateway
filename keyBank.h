/**
 * @file   keyBank.h
 * @author Jonathan Bedard
 * @date   2/14/2016
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
    class nodeGroup
    {
        keyBank* _master;
        os::asyncAVLTree<nodeNameReference> nameList;
        os::asyncAVLTree<nodeKeyReference> keyList;
    public:
        
        nodeGroup(keyBank* master,std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeGroup(){}
        
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
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeNameReference(){}
        
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
        * @param timestamp The time this node was created, 'now' by defult
        */
        nodeKeyReference(nodeGroup* master,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp=os::getTimestamp());
    public:
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~nodeKeyReference(){}
        
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
