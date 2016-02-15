/**
 * @file   keyBank.h
 * @author Jonathan Bedard
 * @date   2/14/2016
 * @brief  Implimentation for the AVL tree based key bank
 * @bug No known bugs.
 *
 * This file contians the implimentation for the
 * crypto::avlKeyBank and supporting classes.
 * Consult keyBank.h for details.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_CPP
#define GATEWAY_CPP

#include "keyBank.h"
#include "cryptoError.h"

namespace crypto {
    
/*-----------------------------------
     Node Group
  -----------------------------------*/
    
    //Node group constructor
    nodeGroup::nodeGroup(keyBank* master,std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
        nameList.insert(os::smart_ptr<nodeNameReference>(new nodeNameReference(this,groupName,name),os::shared_type));
        keyList.insert(os::smart_ptr<nodeKeyReference>(new nodeKeyReference(this,key,algoID,keySize),os::shared_type));
    }
    
/*-----------------------------------
    Node Name Reference
  -----------------------------------*/
    
    //Name reference constructor
    nodeNameReference::nodeNameReference(nodeGroup* master,std::string groupName,std::string name,uint64_t timestamp)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
        _master=master;
        _groupName=groupName;
        _name=name;
        _timestamp=timestamp;
    }
    //Use group name and name to compare
    int nodeNameReference::compare(const nodeNameReference& comp)const
    {
        int compV=_groupName.compare(comp._groupName);
        if(compV>0) return 1;
        else if(compV<0) return -1;
        
        compV=_name.compare(comp._name);
        if(compV>0) return 1;
        else if(compV<0) return -1;
        
        return 0;
    }

/*-----------------------------------
     Node Key Reference
-----------------------------------*/
    
    //Name reference constructor
    nodeKeyReference::nodeKeyReference(nodeGroup* master,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
        if(!key) throw errorPointer(new NULLPublicKey(),os::shared_type);
        
        _master=master;
        _key=key;
        _algoID=algoID;
        _keySize=keySize;
        _timestamp=timestamp;
    }
    //Use group name and name to compare
    int nodeKeyReference::compare(const nodeKeyReference& comp)const
    {return _key.compare(comp._key);}
}

#endif

///@endcond
