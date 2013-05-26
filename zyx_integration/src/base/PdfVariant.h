/***************************************************************************
 *   Copyright (C) 2005 by Dominik Seichter                                *
 *   domseichter@web.de                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef _PDF_VARIANT_H_
#define _PDF_VARIANT_H_

#include <cmath>

#include "PdfDefines.h"
#include "PdfRefCountedBuffer.h"
#include "PdfString.h"

namespace PoDoFo {

class PdfArray;
class PdfData;
class PdfDataType;
class PdfDictionary;
class PdfEncrypt;
class PdfName;
class PdfOutputDevice;
class PdfString;
class PdfReference;

/**
 * A variant data type which supports all data types supported by the PDF standard.
 * The data can be parsed directly from a string or set by one of the members.
 * One can also convert the variant back to a string after setting the values.
 *
 * \warning All methods not marked otherwise may trigger a deferred load. This means
 *          that they are unsafe to call while a deferred load is already in progress
 *          (as recursion will occurr).
 *
 * TODO: domseichter: Make this class implicitly shared
 */
class PODOFO_API PdfVariant {
    friend class PdfArray;
    friend class PdfDictionary;

 public:

    static PdfVariant NullValue;

    /** Construct an empty variant type
     *  IsNull() will return true.
     */
    PdfVariant();

    /** Construct a PdfVariant that is a bool.
     *  \param b the boolean value of this PdfVariant
     */
    PdfVariant( bool b );

    /** Construct a PdfVariant that is a number.
     *  \param l the value of the number.
     */
    PdfVariant( pdf_int64 l );

    /** Construct a PdfVariant that is a real number.
     *  \param d the value of the real number.
     */    
    PdfVariant( double d );

    /** Construct a PdfVariant that is a string. The argument
     * string will be escaped where necessary, so it should be
     * passed in unescaped form.
     *
     *  \param rsString the value of the string
     */        
    PdfVariant( const PdfString & rsString );

    /** Construct a PdfVariant that is a name.
     *  \param rName the value of the name
     */        
    PdfVariant( const PdfName & rName );

    /** Construct a PdfVariant that is a name.
     *  \param rRef the value of the name
     */        
    PdfVariant( const PdfReference & rRef );

    /** Initalize a PdfVariant object with array data.
     *  The variant will automatically get the datatype
     *  ePdfDataType_Array. This Init call is the fastest
     *  way to create a new PdfVariant that is an array.
     *
     *  \param tList a list of variants
     *
     *  \returns ErrOk on sucess
     */
    PdfVariant( const PdfArray & tList );

    /** Construct a PdfVariant that is a dictionary.
     *  \param rDict the value of the dictionary.
     */        
    PdfVariant( const PdfDictionary & rDict );

    /** Construct a PdfVariant that contains raw PDF data.
     *  \param rData raw and valid PDF data.
     */        
    PdfVariant( const PdfData & rData );

    /** Constructs a new PdfVariant which has the same 
     *  contents as rhs.
     *  \param rhs an existing variant which is copied.
     */
    PdfVariant( const PdfVariant & rhs );

    virtual ~PdfVariant();
    
    /** \returns true if this PdfVariant is empty.
     *           i.e. m_eDataType == ePdfDataType_Null
     */
    bool IsEmpty() const;

    /** Clear all internal member variables and free the memory
     *  they have allocated.
     *  Sets the datatype to ePdfDataType_Null
     *
     *  This will reset the dirty flag of this object to be clean.
     *  \see IsDirty
     */
    void Clear();

    /** \returns the datatype of this object or ePdfDataType_Unknown
     *  if it does not have a value.
     */
    EPdfDataType GetDataType() const;

    /** \returns a human readable string representation of GetDataType()
     *  The returned string must not be free'd.
     */
    const char * GetDataTypeString() const;

    /** \returns true if this variant is a bool (i.e. GetDataType() == ePdfDataType_Bool)
     */
    bool IsBool() const;

    /** \returns true if this variant is a number (i.e. GetDataType() == ePdfDataType_Number)
     */
    bool IsNumber() const;

    /** \returns true if this variant is a real (i.e. GetDataType() == ePdfDataType_Real)
     */
    bool IsReal() const;

    /** \returns true if this variant is a string (i.e. GetDataType() == ePdfDataType_String)
     */
    bool IsString() const;

    /** \returns true if this variant is a hex-string (i.e. GetDataType() == ePdfDataType_HexString)
     */
    bool IsHexString() const;

    /** \returns true if this variant is a name (i.e. GetDataType() == ePdfDataType_Name)
     */
    bool IsName() const;

    /** \returns true if this variant is an array (i.e. GetDataType() == ePdfDataType_Array)
     */
    bool IsArray() const;

    /** \returns true if this variant is a dictionary (i.e. GetDataType() == ePdfDataType_Dictionary)
     */
    bool IsDictionary() const;

    /** \returns true if this variant is raw data (i.e. GetDataType() == ePdfDataType_RawData
     */
    bool IsRawData() const;

    /** \returns true if this variant is null (i.e. GetDataType() == ePdfDataType_Null)
     */
    bool IsNull() const;

    /** \returns true if this variant is a reference (i.e. GetDataType() == ePdfDataType_Reference)
     */
    bool IsReference() const;
       
    /** Write the complete variant to an output device.
     *  This is an overloaded member function.
     *
     *  \param pDevice write the object to this device
     *  \param eWriteMode additional options for writing this object
     *  \param pEncrypt an encryption object which is used to encrypt this object
     *                  or NULL to not encrypt this object
     */
    void Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, 
                const PdfEncrypt* pEncrypt = NULL ) const;

    /** Write the complete variant to an output device.
     *  \param pDevice write the object to this device
     *  \param eWriteMode additional options for writing this object
     *  \param pEncrypt an encryption object which is used to encrypt this object
     *                  or NULL to not encrypt this object
     *  \param keyStop if not KeyNull and a key == keyStop is found
     *                 writing will stop right before this key!
     *                 if IsDictionary returns true.
     */
    virtual void Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, const PdfEncrypt* pEncrypt, const PdfName & keyStop ) const;

    /** Converts the current object into a string representation
     *  which can be written directly to a PDF file on disc.
     *  \param rsData the object string is returned in this object.
     *  \param eWriteMode additional options for writing to a string
     */
    void ToString( std::string & rsData, EPdfWriteMode eWriteMode = ePdfWriteMode_Clean ) const;

    /** Set the value of this object as bool
     *  \param b the value as bool.
     *
     *  This will set the dirty flag of this object.
     *  \see IsDirty
     */
    void SetBool( bool b );

    /** Get the value if this object is a bool.
     *  \returns the bool value.
     */
    bool GetBool() const;

    /** Set the value of this object as long
     *  \param l the value as long.
     *
     *  This will set the dirty flag of this object.
     *  \see IsDirty
     */
    void SetNumber( long l );

    /** Get the value of the object as long.
     *  \return the value of the number
     */
    pdf_int64 GetNumber() const;

    /** Set the value of this object as double
     *  \param d the value as double.
     *
     *  This will set the dirty flag of this object.
     *  \see IsDirty
     */
    void SetReal( double d );

    /** Get the value of the object as double.
     *  \return the value of the number
     */
    double GetReal() const;

    /** \returns the value of the object as string.
     */
    const PdfString & GetString() const;

    /** \returns the value of the object as name
     */
    const PdfName & GetName() const;

    /** Returns the value of the object as array
     *  \returns a array
     */
    const PdfArray & GetArray() const;

    /** Returns the value of the object as array
     *  \returns a array
     */
    PdfArray & GetArray();

    /** Returns the dictionary value of this object
     *  \returns a PdfDictionary
     */
    const PdfDictionary & GetDictionary() const; 

    /** Returns the dictionary value of this object
     *  \returns a PdfDictionary
     */
    PdfDictionary & GetDictionary(); 

    /** Get the reference values of this object.
     *  \returns a PdfReference
     */
    const PdfReference & GetReference() const;

    /** Get the reference values of this object.
     *  \returns a reference to the PdfData instance.
     */
    const PdfData & GetRawData() const;

    /** Get the reference values of this object.
     *  \returns a reference to the PdfData instance.
     */
    PdfData & GetRawData();

    /** Assign the values of another PdfVariant to this one.
     *  \param rhs an existing variant which is copied.
     *
     *  This will set the dirty flag of this object.
     *  \see IsDirty
     */
    const PdfVariant & operator=( const PdfVariant & rhs );

    /**
     * Test to see if the value contained by this variant is the same
     * as the value of the other variant.
     */
    bool operator==( const PdfVariant & rhs ) const;

    /**
     * \see operator==
     */
    bool operator!=( const PdfVariant & rhs) const;

    /** The dirty flag is set if this variant
     *  has been modified after construction.
     *  
     *  Usually the dirty flag is also set
     *  if you call any non-const member function
     *  (e.g. GetDictionary()) as PdfVariant cannot
     *  determine if you actually changed the dictionary
     *  or not.
     *
     *  \returns true if the value is dirty and has been 
     *                modified since construction
     */
    bool IsDirty() const;

    /**
     * Sets this object to immutable,
     * so that no keys can be edited or changed.
     *
     * @param bImmutable if true set the object to be immutable
     *
     * This is used by PdfImmediateWriter and PdfStreamedDocument so 
     * that no keys can be added to an object after setting stream data on it.
     *
     */
    void SetImmutable(bool bImmutable);

    /**
     * Retrieve if an object is immutable.
     *
     * This is used by PdfImmediateWriter and PdfStreamedDocument so 
     * that no keys can be added to an object after setting stream data on it.
     *
     * @returns true if the object is immutable
     */
    bool GetImmutable() const;

 protected:

    /**
     *  Will throw an exception if called on an immutable object,
     *  so this should be called before actually changing a value!
     * 
     */
    void AssertMutable() const;

    /** Sets the dirty flag of this PdfVariant
     *
     *  \param bDirty true if this PdfVariant has been
     *                modified from the outside
     *
     *  \see IsDirty
     */
    void SetDirty( bool bDirty );

    /**
     * Dynamically load the contents of this object from a PDF file by calling
     * the virtual method DelayedLoadImpl() if the object is not already loaded.
     *
     * For objects complete created in memory and those that do not support
     * deferred loading this function does nothing, since deferred loading
     * will not be enabled.
     */
    void DelayedLoad() const;

    /** Flag the object  incompletely loaded.  DelayedLoad() will be called
     *  when any method that requires more information than is currently
     *  available is loaded.
     *
     *  All constructors initialize a PdfVariant with delayed loading disabled .
     *  If you want delayed loading you must ask for it. If you do so, call
     *  this method early in your ctor and be sure to override DelayedLoadImpl().
     */
    void EnableDelayedLoading();

    /** Load all data of the object if delayed loading is enabled.
     *
     * Never call this method directly; use DelayedLoad() instead.
     *
     * You should override this to control deferred loading in your subclass.
     * Note that this method should not load any associated streams, just the
     * base object.
     *
     * The default implementation throws. It should never be called, since
     * objects that do not support delayed loading should not enable it.
     *
     * While this method is not `const' it may be called from a const context,
     * so be careful what you mess with.
     */
    virtual void DelayedLoadImpl();

    /**
     * Returns true if delayed loading is disabled, or if it is enabled
     * and loading has completed. External callers should never need to
     * see this, it's an internal state flag only.
     */
    PODOFO_NOTHROW bool DelayedLoadDone() const;

    // Rather than having deferred load triggering disabled while deferred
    // loading is in progress, causing public methods to potentially return
    // invalid data, we provide special methods that won't trigger a deferred
    // load for use during deferred loading. They're not for general use and
    // not available for use except by subclasses.
    //
    /** Version of GetDictionary() that doesn't trigger a delayed load
     *  \returns a PdfDictionary
     */
    const PdfDictionary & GetDictionary_NoDL() const; 

    /** Version of GetDictionary() that doesn't trigger a delayed load
     *  \returns a PdfDictionary
     */
    PdfDictionary & GetDictionary_NoDL(); 

    /** Version of GetArray() that doesn't trigger a delayed load
     *  \returns a array
     */
    const PdfArray & GetArray_NoDL() const;

    /** Version of GetArray() that doesn't trigger a delayed load.
     *  \returns a array
     */
    PdfArray & GetArray_NoDL();

 private:
    /**
     * It's an easy mistake to pass a pointer to a PdfVariant when trying to
     * copy a PdfVariant, especially with heap allocators like `new'. This can
     * produce confusing and unexpected results like getting a PdfVariant(bool).
     *
     * A similar issue can arise when the user passes a `char*' and expects a PdfName
     * or PdfString based variant to be created. We can't know which they wanted, so
     * we should fail, especially since the compiler tends to convert pointers to bool
     * for extra confusion value.
     *
     * We provide this overload so that such attempts will fail with an error about
     * a private ctor. If you're reading this, you wrote:
     *
     *  PdfVariant( my_ptr_to_something )
     *
     *... not ...
     * 
     *  PdfVariant( *my_ptr_to_something )
     *
     * If you need to modify PdfVariant to legitimately take a pointer in the future,
     * you can do so by providing a template specialization, or by removing this check
     * and replacing it with a couple of overloads specific to PdfObject*, PdfVariant*,
     * and char* (at least).
     */
    template<typename T> PdfVariant(T*);

    /** To reduce memory usage of this very often used class,
     *  we use a union here, as there is always only
     *  one of those members used.
     */
    typedef union { 
        /** Holds references, strings, 
         *  names, dictionaries and arrays
         */
        PdfDataType* pData;

        bool       bBoolValue;
        double     dNumber;
        pdf_int64      nNumber;
    } UVariant;

    UVariant     m_Data;

    bool         m_bDirty; ///< Indicates if this object was modified after construction
    bool         m_bImmutable; ///< Indicates if this object maybe modified


    /** Datatype of the variant.
     *  required to access the correct member of 
     *  the union UVariant.
     */
    EPdfDataType m_eDataType;

    // No touchy. Only for use by PdfVariant's internal tracking of the delayed
    // loading state. Use DelayedLoadDone() to test this if you need to.
    mutable bool m_bDelayedLoadDone;

    // Helper for ctor
    PODOFO_NOTHROW void Init();

#if defined(PODOFO_EXTRA_CHECKS)
protected:
    PODOFO_NOTHROW bool DelayedLoadInProgress() const
private:
    mutable bool m_bDelayedLoadInProgress;
#endif
};

};

#endif // _PDF_VARIANT_H_
