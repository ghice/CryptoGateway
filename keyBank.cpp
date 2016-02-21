/**
 * @file   keyBank.cpp
 * @author Jonathan Bedard
 * @date   2/20/2016
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
		_master=master;

		sortingLock.lock();
		os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,groupName,name),os::shared_type);
        if(nameList.insert(nameInsert))
			_master->pushNewNode(nameInsert);
		else throw errorPointer(new insertionFailed(),os::shared_type);
		os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,algoID,keySize),os::shared_type);
        if(keyList.insert(keyInsert))
			_master->pushNewNode(keyInsert);
		else throw errorPointer(new insertionFailed(),os::shared_type);
		sortKeys();
		sortNames();
		sortingLock.unlock();
    }
	//Returns the name of a node group
	void nodeGroup::getName(std::string& groupName,std::string& name)
	{
		sortingLock.lock();
		
		//No array case
		if(!sortedNames || !sortedNames[0])
		{
			groupName="";
			name="";
		}
		else
		{
			groupName=sortedNames[0]->groupName();
			name=sortedNames[1]->groupName();
		}
		sortingLock.unlock();
	}
	//Returns the name of a node group
	std::string nodeGroup::name()
	{
		std::string gn,nm;
		getName(gn,nm);
		return gn+":"+nm;
	}
	
	//Merges two node groups
	void nodeGroup::merge(nodeGroup& source)
	{
		sortingLock.lock();
		if(source._master!=_master) throw errorPointer(new masterMismatch(),os::shared_type);
		auto trc1=source.nameList.getFirst();
		while(trc1)
		{
			trc1->getData()->_master=this;
			nameList.insert(trc1->getData());
			trc1=trc1->getNext();
		}
		auto trc2=source.keyList.getFirst();
		while(trc2)
		{
			trc2->getData()->_master=this;
			keyList.insert(trc2->getData());
			trc2=trc2->getNext();
		}
		sortKeys();
		sortNames();
		sortingLock.unlock();
	}
	//Adds an alias to the current node
	void nodeGroup::addAlias(std::string groupName,std::string name,uint64_t timestamp)
	{
		sortingLock.lock();
		os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,groupName,name,timestamp),os::shared_type);
        if(nameList.insert(nameInsert))
			_master->pushNewNode(nameInsert);
		sortNames();
		sortingLock.unlock();
	}
	//Adds a key to the current node
	void nodeGroup::addKey(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp)
	{
		sortingLock.lock();
		os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,algoID,keySize,timestamp),os::shared_type);
        if(keyList.insert(keyInsert))
			_master->pushNewNode(keyInsert);
		sortKeys();
		sortingLock.unlock();
	}

	//Compare keys by timestamp
	int compareKeysByTimestamp(os::smart_ptr<nodeKeyReference> ref1, os::smart_ptr<nodeKeyReference> ref2)
	{
		if(ref1->timestamp()>ref2->timestamp())
			return 1;
		if(ref1->timestamp()<ref2->timestamp())
		return 0;
	}
	//Compare names by timestamp
	int compareNamesByTimestamp(os::smart_ptr<nodeNameReference> ref1, os::smart_ptr<nodeNameReference> ref2)
	{
		if(ref1->timestamp()>ref2->timestamp())
			return 1;
		if(ref1->timestamp()<ref2->timestamp())
		return 0;
	}
	//Preforms quicksort on keys by timestamp
	void nodeGroup::sortKeys()
	{
		sortedKeys=os::smart_ptr<os::smart_ptr<nodeKeyReference> >(new os::smart_ptr<nodeKeyReference>[keyList.size()],os::shared_type_array);
		unsigned int cnt=0;
		for(auto i=keyList.getFirst();i;i=i->getNext())
		{
			sortedKeys[cnt]=i->getData();
			cnt++;
		}
		os::pointerQuicksort(sortedKeys,cnt,&compareKeysByTimestamp);
	}
	//Preforms quicksort on names by timestamp
	void nodeGroup::sortNames()
	{
		sortedNames=os::smart_ptr<os::smart_ptr<nodeNameReference> >(new os::smart_ptr<nodeNameReference>[nameList.size()],os::shared_type_array);
		unsigned int cnt=0;
		for(auto i=nameList.getFirst();i;i=i->getNext())
		{
			sortedKeys[cnt]=i->getData();
			cnt++;
		}
		os::pointerQuicksort(sortedKeys,cnt,&compareKeysByTimestamp);
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
    //Designed for searching
	nodeNameReference::nodeNameReference(std::string groupName,std::string name)
	{
		_master=NULL;
        _groupName=groupName;
        _name=name;
        _timestamp=os::getTimestamp();
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
    //Designed for seraching
	nodeKeyReference::nodeKeyReference(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
	{
		if(!key) throw errorPointer(new NULLPublicKey(),os::shared_type);

		_master=NULL;
        _key=key;
        _algoID=algoID;
        _keySize=keySize;
        _timestamp=os::getTimestamp();
	}
	//Use group name and name to compare
    int nodeKeyReference::compare(const nodeKeyReference& comp)const
    {return _key.compare(comp._key);}
}

#endif

///@endcond
