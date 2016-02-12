//Primary author: Jonathan Bedard
//Certified working 2/12/2016

#ifndef XML_ENCRYPTION_CPP
#define XML_ENCRYPTION_CPP

#include <string>
#include <stdint.h>
#include "XMLEncryption.h"
#include "cryptoError.h"

namespace crypto {

    //Generate arguments list
	static std::vector<std::string> generateArgumentList(os::smartXMLNode head)
	{
		std::vector<std::string> ret;
		unsigned int trc1=0;
		unsigned int trc2=0;

		ret.push_back(head->getID());
		std::vector<std::string> temp;
		for(auto it=head->getChildren()->getFirst();it;it=it->getNext())
		{
			temp=generateArgumentList(it->getData());
			for(trc1=0;trc1<temp.size();trc1++)
			{
				bool found=false;
				for(trc2=0;trc2<ret.size()&&!found;trc2++)
				{
					if(ret[trc2]==temp[trc1])
						found=true;
				}
				if(!found) ret.push_back(temp[trc1]);
			}
		}

		return ret;
	}
    //Given an XML node, a stream encryptor, an argument vector and a file, print it
	static void recursiveXMLPrinting(os::smartXMLNode head,os::smart_ptr<streamCipher> strm,std::vector<std::string> args,std::ofstream& ofs)
	{
		//Throw -1 if error
		if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
		if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);

		//Contains: index, number of children, amount of data
		unsigned char headerData [6];
		memset(headerData,0,6);
		uint16_t data=args.size()+1;

		//Index
		for(unsigned int i=0;i<args.size()&&data>args.size();i++)
		{
			if(args[i]==head->getID())
				data=i;
		}
		data=os::to_comp_mode(data);
		memcpy(headerData,&data,2);

		//Number of children
		if(head->getChildren()->size()>0)
		{
			data=head->getChildren()->size();
			data=os::to_comp_mode(data);
			memcpy(headerData+2,&data,2);
		}
		//Amount of data
		else
		{
			data=0;
			if(head->getData()!="")
				data=1;
			else if(head->getDataList().size()>0)
				data=head->getDataList().size();
			data=os::to_comp_mode(data);
			memcpy(headerData+4,&data,2);
		}

		for(unsigned int i=0;i<6;i++)
			headerData[i]^=strm->getNext();
		ofs.write((char*)headerData,6);

		//Output children
		if(head->getChildren()->size()>0)
		{
			for(auto trc=head->getChildren()->getFirst();trc;trc=trc->getNext())
				recursiveXMLPrinting(trc->getData(),strm,args,ofs);
		}
		//Output data
		else
		{
			os::smart_ptr<unsigned char> dataptr;
			if(head->getData()!="")
			{
				dataptr=os::smart_ptr<unsigned char>(new unsigned char[head->getData().size()+2],os::shared_type_array);
				data=head->getData().size();
				data=os::to_comp_mode(data);
				memcpy(dataptr.get(),&data,2);
				memcpy(dataptr.get()+2,head->getData().c_str(),head->getData().size());
				for(unsigned int en=0;en<head->getData().size()+2;en++)
					dataptr[en]=dataptr[en]^strm->getNext();
				ofs.write((char*)dataptr.get(),head->getData().size()+2);
			}
			else
			{
				for(unsigned int i=0;i<head->getDataList().size();i++)
				{
					dataptr=os::smart_ptr<unsigned char>(new unsigned char[head->getDataList()[i].size()+2],os::shared_type_array);
					data=head->getDataList()[i].size();
					data=os::to_comp_mode(data);
					memcpy(dataptr.get(),&data,2);
					memcpy(dataptr.get()+2,head->getDataList()[i].c_str(),head->getDataList()[i].size());
					for(unsigned int en=0;en<head->getDataList()[i].size()+2;en++)
						dataptr[en]=dataptr[en]^strm->getNext();
					ofs.write((char*)dataptr.get(),head->getDataList()[i].size()+2);
				}
			}
		}
	}
	//Build an XML tree from an EXML file
	static os::smartXMLNode recursiveXMLBuilding(os::smart_ptr<streamCipher> strm,std::vector<std::string> args,std::ifstream& ifs)
	{
		if(!strm) throw errorPointer(new NULLDataError(),os::shared_type);
		if(!ifs.good()) throw errorPointer(new actionOnFileError(),os::shared_type);
		unsigned char headerData [6];

		ifs.read((char*)headerData,6);
		//Decrypt
		for(unsigned int i=0;i<6;i++)
			headerData[i]=headerData[i]^strm->getNext();
		uint16_t data;

		//Index
		memcpy(&data,headerData,2);
		data=os::from_comp_mode(data);
		if(data>=args.size()) throw errorPointer(new customError("ID Index out-of-bound","Expected index less than "+std::to_string(args.size())+" but found index "+std::to_string(data)),os::shared_type);
		os::smartXMLNode ret(new os::XML_Node(args[data]),os::shared_type);

		//Number of children
		memcpy(&data,headerData+2,2);
		data=os::from_comp_mode(data);
		if(data>0)
		{
			for(unsigned int i=0;i<data;i++)
			{
				if(!ifs.good()) throw errorPointer(new actionOnFileError(),os::shared_type);
				ret->addElement(recursiveXMLBuilding(strm,args,ifs));
			}
			return ret;
		}

		//Amount of data
		memcpy(&data,headerData+4,2);
		data=os::from_comp_mode(data);
		std::vector<std::string> pData;
		for(unsigned int i=0;i<data;i++)
		{
			if(!ifs.good()) throw errorPointer(new actionOnFileError(),os::shared_type);
			//Find string length
			uint16_t strLen;

			ifs.read((char*)headerData,2);
			headerData[0]=headerData[0]^strm->getNext();
			headerData[1]=headerData[1]^strm->getNext();
			memcpy(&strLen,headerData,2);
			strLen=os::from_comp_mode(strLen);
			char* str=new char[strLen+1];
			ifs.read(str,strLen);
			for(unsigned s=0;s<strLen;s++)
				str[s]=str[s]^strm->getNext();
			str[strLen]='\0';
			pData.push_back(std::string(str));
			delete [] str;
		}
		if(pData.size()==1) ret->setData(pData[0]);
		else
		{
			for(unsigned int i=0;i<pData.size();i++)
				ret->getDataList().push_back(pData[i]);
		}

		return ret;
	}

	//Raw password output
    bool EXML_Output(std::string path, os::smartXMLNode head, std::string password, os::smart_ptr<streamPackageFrame> spf)
    {
		try
		{
			//Basic checks
			if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);;
			std::ofstream fileout(path);
			if(!fileout.good()) throw errorPointer(new fileOpenError(),os::shared_type);
        
			//Check stream package
			if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
			//Output header
			fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
			os::smartXMLNode encryHead(new os::XML_Node("header"),os::shared_type);
        
			//Public key type
			os::smartXMLNode trc1(new os::XML_Node("public_key"),os::shared_type);
			os::smartXMLNode trc2;
			trc1->setData("none");
			encryHead->addElement(trc1);
        
			//Stream
			trc1=os::smartXMLNode(new os::XML_Node("stream"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->streamAlgorithmName());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Hash
			trc1=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->hashAlgorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string(spf->hashSize()*8));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Key
			trc1=os::smartXMLNode(new os::XML_Node("key"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			hash hsh=spf->hashData((unsigned char*)password.c_str(),password.size());
			trc2->setData(hsh.toString());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Data list
			std::vector<std::string> argList=generateArgumentList(head);
			trc1=os::smartXMLNode(new os::XML_Node("argList"),os::shared_type);
			for(unsigned int i=0;i<argList.size();i++)
				trc1->getDataList().push_back(argList[i]);
			encryHead->addElement(trc1);

			os::xml::writeNode(fileout,encryHead,0);

			os::smart_ptr<streamCipher> strm=spf->buildStream((unsigned char*)password.c_str(),password.size());
			if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			fileout<<'>';
			recursiveXMLPrinting(head,strm,argList,fileout);
		}
		catch(errorPointer e)
		{throw e;}
		catch(int e)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string(e)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
        
        return true;
    }
    //Public key encryption output
    bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<publicKey> pbk, os::smart_ptr<streamPackageFrame> spf)
    {
		try
		{
			//Basic checks
			if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			if(!pbk) throw errorPointer(new NULLDataError(),os::shared_type);
			std::ofstream fileout(path);
			if(!fileout.good()) throw errorPointer(new fileOpenError(),os::shared_type);
        
			//Check stream package
			if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
			//Output header
			fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
			os::smartXMLNode encryHead(new os::XML_Node("header"),os::shared_type);
        
			//Public key type
			os::smartXMLNode trc1(new os::XML_Node("public_key"),os::shared_type);
			os::smartXMLNode trc2(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(pbk->algorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string(pbk->size()*32));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Stream
			trc1=os::smartXMLNode(new os::XML_Node("stream"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->streamAlgorithmName());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Hash
			trc1=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->hashAlgorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string(spf->hashSize()*8));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Generate key, and hash
			srand(time(NULL));
			os::smart_ptr<unsigned char> randkey=os::smart_ptr<unsigned char>(new unsigned char[pbk->size()*4],os::shared_type_array);
			memset(randkey.get(),0,pbk->size()*4);
			for(unsigned int i=0;i<(pbk->size()-1)*4;i++)
				randkey[i]=rand();
			os::smart_ptr<number> num=pbk->copyConvert(randkey.get(),pbk->size()*4);
			num->reduce();
			unsigned int keylen;
			os::smart_ptr<unsigned char> raw_key=num->getCompCharData(keylen);
			if(!raw_key) throw errorPointer(new hashGenerationError(),os::shared_type);
			hash hsh=spf->hashData(raw_key.get(),keylen);
			num=pbk->encode(num);
			num->reduce();

			//Key
			trc1=os::smartXMLNode(new os::XML_Node("key"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2->setData(hsh.toString());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("encryptedKey"),os::shared_type);
			trc2->setData(num->toString());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Data list
			std::vector<std::string> argList=generateArgumentList(head);
			trc1=os::smartXMLNode(new os::XML_Node("argList"),os::shared_type);
			for(unsigned int i=0;i<argList.size();i++)
				trc1->getDataList().push_back(argList[i]);
			encryHead->addElement(trc1);
        
			os::xml::writeNode(fileout,encryHead,0);

			os::smart_ptr<streamCipher> strm=spf->buildStream(raw_key.get(),keylen);
			if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			fileout<<'>';
			recursiveXMLPrinting(head,strm,argList,fileout);
		}
		catch(errorPointer e)
		{throw e;}
		catch(int e)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string(e)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
        
        return true;
    }
    //Decrypt with password
    os::smartXMLNode EXML_Input(std::string path, std::string password)
    {
		os::smartXMLNode ret;
		try
		{
			//Basic checks
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			std::ifstream filein(path);
			if(!filein.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Check header
			os::xml::readTillTag(filein);
			std::string temp = os::xml::readThroughTag(filein);
			if(temp != "?exml") throw errorPointer(new fileFormatError(),os::shared_type);

			//Parse header
			os::smartXMLNode enhead=os::xml::parseNode(filein);
			os::smartXMLNode trc1;
			os::smartXMLNode trc2;
			os::smart_ptr<os::adnode<os::XML_Node> > fnd;
			std::string streamID;
			std::string hashID;
			unsigned int hashSize;

			//Test ID
			if(!enhead) throw errorPointer(new fileOpenError(),os::shared_type);
			if(enhead->getID()!="header") throw errorPointer(new fileFormatError(),os::shared_type);

			//Public key
			fnd=enhead->findElement("public_key")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="none") throw errorPointer(new illegalAlgorithmBind("Expected NULL Public Key"),os::shared_type);

			//Stream
			fnd=enhead->findElement("stream")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileOpenError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				streamID=trc2->getData();

			//Hash
			fnd=enhead->findElement("hash")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileOpenError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashID=trc2->getData();

				//Size
				fnd=trc1->findElement("size")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashSize = std::stoi(trc2->getData())/8;

			//Bind encryption stream
			os::smart_ptr<streamPackageFrame> spf=streamPackageTypeBank::singleton()->findStream(streamID,hashID);
			if(!spf) throw errorPointer(new fileFormatError(),os::shared_type);
			spf=spf->getCopy();
			spf->setHashSize(hashSize);

			//Key manipulation
			fnd=enhead->findElement("key")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileOpenError(),os::shared_type);
			
				//Hash
				fnd=trc1->findElement("hash")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hash refHash=spf->hashData((unsigned char*)password.c_str(),password.size());
				hash compHash(refHash);
				compHash.fromString(trc2->getData());
				if(refHash!=compHash) throw errorPointer(new hashCompareError(),os::shared_type);

			//Arg list
			fnd=enhead->findElement("argList")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			std::vector<std::string> argList;
			if(trc1->getData()=="")
				argList=trc1->getDataList();
			else
				argList.push_back(trc1->getData());
			
			while(filein.get()!='>');
			ret=recursiveXMLBuilding(spf->buildStream((unsigned char*) password.c_str(),password.length()),argList,filein);
		}
		catch(errorPointer e)
		{throw e;}
		catch(int e)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string(e)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}

        return ret;
    }
    //Decrypt with public key
    os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk)
    {
		os::smartXMLNode ret;
		try
		{
			//Basic checks
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			if(!pbk) throw errorPointer(new NULLDataError(),os::shared_type);
			std::ifstream filein(path);
			if(!filein.good()) throw errorPointer(new fileOpenError(),os::shared_type);
		
			//Check header
			os::xml::readTillTag(filein);
			std::string temp = os::xml::readThroughTag(filein);
			if(temp != "?exml")
				throw errorPointer(new fileFormatError(),os::shared_type);

			//Parse header
			os::smartXMLNode enhead=os::xml::parseNode(filein);
			os::smartXMLNode trc1;
			os::smartXMLNode trc2;
			os::smart_ptr<os::adnode<os::XML_Node> > fnd;
			std::string streamID;
			std::string hashID;
			unsigned int hashSize;

			//Test ID
			if(!enhead) throw errorPointer(new fileFormatError(),os::shared_type);
			if(enhead->getID()!="header") throw errorPointer(new fileFormatError(),os::shared_type);

			//Public key
			fnd=enhead->findElement("public_key")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);

				//Algorithm
				fnd=trc1->findElement("algo")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				if(trc2->getData()!=pbk->algorithmName()) throw errorPointer(new illegalAlgorithmBind(trc2->getData()+" vs "+pbk->algorithmName()),os::shared_type);

				//Size
				fnd=trc1->findElement("size")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				if(std::stoi(trc2->getData())/32!=pbk->size()) throw errorPointer(new illegalAlgorithmBind(trc2->getData()+" vs "+std::to_string(pbk->size())),os::shared_type);

			//Stream
			fnd=enhead->findElement("stream")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				streamID=trc2->getData();

			//Hash
			fnd=enhead->findElement("hash")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashID=trc2->getData();

				//Size
				fnd=trc1->findElement("size")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashSize = std::stoi(trc2->getData())/8;

			//Bind encryption stream
			os::smart_ptr<streamPackageFrame> spf=streamPackageTypeBank::singleton()->findStream(streamID,hashID);
			if(!spf) throw errorPointer(new fileFormatError(),os::shared_type);
			spf=spf->getCopy();
			spf->setHashSize(hashSize);

			//Key manipulation
			fnd=enhead->findElement("key")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);
			
				//Raw Key
				fnd=trc1->findElement("encryptedKey")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				os::smart_ptr<number> num(new number(),os::shared_type);
				num->fromString(trc2->getData());
				num=pbk->copyConvert(num);
				num=pbk->decode(num.get());
				num->reduce();

				//Hash
				fnd=trc1->findElement("hash")->getFirst();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=fnd->getData();
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				unsigned int keylen;
				os::smart_ptr<unsigned char> raw_key=num->getCompCharData(keylen);
				if(!raw_key) throw errorPointer(new hashGenerationError(),os::shared_type);
				hash refHash=spf->hashData(raw_key.get(),keylen);
				hash compHash(refHash);
				compHash.fromString(trc2->getData());
				if(refHash!=compHash) throw errorPointer(new hashCompareError(),os::shared_type);

			//Arg list
			fnd=enhead->findElement("argList")->getFirst();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=fnd->getData();
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			std::vector<std::string> argList;
			if(trc1->getData()=="")
				argList=trc1->getDataList();
			else
				argList.push_back(trc1->getData());

			while(filein.get()!='>');

			ret=ret=recursiveXMLBuilding(spf->buildStream((unsigned char*) raw_key.get(),keylen),argList,filein);
		}
		catch(errorPointer e1)
		{throw e1;}
		catch(int e2)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string(e2)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
        
        return ret;
    }
}

#endif
