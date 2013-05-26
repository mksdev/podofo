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

#include "PdfVariant.h"

#include "PdfArray.h"
#include "PdfData.h"
#include "PdfDictionary.h"
#include "PdfOutputDevice.h"
#include "PdfParserObject.h"
#include "PdfDefinesPrivate.h"

#include <sstream>

#include <string.h>

namespace PoDoFo {

using namespace std;

PdfVariant PdfVariant::NullValue;

// Do one-off initialization that should not be repeated
// in the Clear() method. Mostly useful for internal sanity checks.
inline void PdfVariant::Init()
{
    // DS: These members will be set in ::Clear()
    //     which is called by every constructor.
    // m_bDelayedLoadDone = true;
    // m_bDirty = false;

    // Has to be done in Init so that Clear() works
    // and can delete data if necessary
    memset( &m_Data, 0, sizeof( UVariant ) );
    // Has to be set as Clear() depends on it
    m_eDataType = ePdfDataType_Null;
    m_bImmutable = false;

#if defined(PODOFO_EXTRA_CHECKS)
    m_bDelayedLoadInProgress=false;
#endif
}

PdfVariant::PdfVariant()
{
    Init();
    Clear();

    m_eDataType = ePdfDataType_Null;
}

PdfVariant::PdfVariant( bool b )
{
    Init();
    Clear();

    m_eDataType       = ePdfDataType_Bool;
    m_Data.bBoolValue = b;
}

PdfVariant::PdfVariant( pdf_int64 l )
{
    Init();
    Clear();

    m_eDataType       = ePdfDataType_Number;
    m_Data.nNumber    = l;
}

PdfVariant::PdfVariant( double d )
{
    Init();
    Clear();

    m_eDataType       = ePdfDataType_Real;
    m_Data.dNumber    = d;    
}

PdfVariant::PdfVariant( const PdfString & rsString )
{
    Init();
    Clear();

    m_eDataType  = rsString.IsHex() ? ePdfDataType_HexString : ePdfDataType_String;
    m_Data.pData = new PdfString( rsString );
}

PdfVariant::PdfVariant( const PdfName & rName )
{
    Init();
    Clear();

    m_eDataType  = ePdfDataType_Name;
    m_Data.pData = new PdfName( rName );
}

PdfVariant::PdfVariant( const PdfReference & rRef )
{
    Init();
    Clear();

    m_eDataType  = ePdfDataType_Reference;
    m_Data.pData = new PdfReference( rRef );
}

PdfVariant::PdfVariant( const PdfArray & rArray )
{
    Init();
    Clear();

    m_eDataType  = ePdfDataType_Array;
    m_Data.pData = new PdfArray( rArray );
}

PdfVariant::PdfVariant( const PdfDictionary & rObj )
{
    Init();
    Clear();

    m_eDataType  = ePdfDataType_Dictionary;
    m_Data.pData = new PdfDictionary( rObj );
}

PdfVariant::PdfVariant( const PdfData & rData )
{
    Init();
    Clear();

    m_eDataType  = ePdfDataType_RawData;
    m_Data.pData = new PdfData( rData );
}

PdfVariant::PdfVariant( const PdfVariant & rhs )
{
    Init();
    this->operator=(rhs);

    SetDirty( false );
}

PdfVariant::~PdfVariant()
{
    m_bImmutable = false; // Destructor may change things, i.e. delete
    Clear();
}

void PdfVariant::Clear()
{
    switch( m_eDataType ) 
    {
        case ePdfDataType_Array:
        case ePdfDataType_Reference:
        case ePdfDataType_Dictionary:
        case ePdfDataType_Name:
        case ePdfDataType_String:
        case ePdfDataType_HexString:
        case ePdfDataType_RawData:
        {
            if( m_Data.pData )
                delete m_Data.pData;
            break;
        }
            
        case ePdfDataType_Bool:
        case ePdfDataType_Null:
        case ePdfDataType_Number:
        case ePdfDataType_Real:
        case ePdfDataType_Unknown:
        default:
            break;
            
    }

    m_bDelayedLoadDone = true;
#if defined(PODOFO_EXTRA_CHECKS)
	m_bDelayedLoadInProgress = false;
#endif
	m_bDirty           = false; 
    m_eDataType        = ePdfDataType_Null;
    m_bImmutable       = false;

    memset( &m_Data, 0, sizeof( UVariant ) );
}

void PdfVariant::Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, const PdfEncrypt* pEncrypt ) const
{
    this->Write( pDevice, eWriteMode, pEncrypt, PdfName::KeyNull );
}

void PdfVariant::Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, const PdfEncrypt* pEncrypt, const PdfName & keyStop ) const
{
    DelayedLoad(); 

    /* Check all handles first 
     */
    if( (m_eDataType == ePdfDataType_HexString ||
         m_eDataType == ePdfDataType_String ||
         m_eDataType == ePdfDataType_Array ||
         m_eDataType == ePdfDataType_Dictionary ||
         m_eDataType == ePdfDataType_Name || 
         m_eDataType == ePdfDataType_RawData ) && !m_Data.pData )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    switch( m_eDataType ) 
    {
        case ePdfDataType_Bool:
        {
            if( (eWriteMode & ePdfWriteMode_Compact) == ePdfWriteMode_Compact ) 
            {
                pDevice->Write( " ", 1 ); // Write space before true or false
            }

            if( m_Data.bBoolValue )
                pDevice->Write( "true", 4 );
            else
                pDevice->Write( "false", 5 );
            break;
        }
        case ePdfDataType_Number:
        {
            if( (eWriteMode & ePdfWriteMode_Compact) == ePdfWriteMode_Compact ) 
            {
                pDevice->Write( " ", 1 ); // Write space before numbers
            }

#ifdef _WIN64
            pDevice->Print( "%" PDF_FORMAT_INT64, m_Data.nNumber );
#else
            pDevice->Print( "%" PDF_FORMAT_INT64, m_Data.nNumber );
#endif
            break;
        }
        case ePdfDataType_Real:
            //pDevice->Print( "%g", m_Data.dNumber );
            // DominikS: %g precision might write floating points
            //           numbers in exponential form (with e)
            //           which is not supported in PDF.
            //           %f fixes this but might loose precision as 
            //           it defaults to a precision of 6
            // pDevice->Print( "%f", m_Data.dNumber );
        {
            if( (eWriteMode & ePdfWriteMode_Compact) == ePdfWriteMode_Compact ) 
            {
                pDevice->Write( " ", 1 ); // Write space before numbers
            }

            // Use ostringstream, so that locale does not matter
            std::ostringstream oss;
            PdfLocaleImbue(oss);
            oss << std::fixed << m_Data.dNumber;

            pDevice->Write( oss.str().c_str(), oss.str().size() );
            break;
        }
        case ePdfDataType_HexString:
        case ePdfDataType_String:
        case ePdfDataType_Name:
        case ePdfDataType_Array:
        case ePdfDataType_Reference:
        case ePdfDataType_RawData:
            m_Data.pData->Write( pDevice, eWriteMode, pEncrypt );
            break;
        case ePdfDataType_Dictionary:
            static_cast<PdfDictionary*>(m_Data.pData)->Write( pDevice, eWriteMode, pEncrypt, keyStop );
            break;
        case ePdfDataType_Null:
        {
            if( (eWriteMode & ePdfWriteMode_Compact) == ePdfWriteMode_Compact ) 
            {
                pDevice->Write( " ", 1 ); // Write space before null
            }

            pDevice->Print( "null" );
            break;
        }
        case ePdfDataType_Unknown:
        default:
        {
            PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
            break;
        }
    };
}

void PdfVariant::ToString( std::string & rsData, EPdfWriteMode eWriteMode ) const
{
    ostringstream   out;
    // We don't need to this stream with the safe PDF locale because
    // PdfOutputDevice will do so for us.
    PdfOutputDevice device( &out );

    this->Write( &device, eWriteMode, NULL );
    
    rsData = out.str();
}

const PdfVariant & PdfVariant::operator=( const PdfVariant & rhs )
{
    Clear();

    rhs.DelayedLoad();

    m_eDataType      = rhs.m_eDataType;
    
    switch( m_eDataType ) 
    {
        case ePdfDataType_Array:
        {
            if( rhs.m_Data.pData ) 
                m_Data.pData = new PdfArray( *(static_cast<PdfArray*>(rhs.m_Data.pData)) );
            break;
        }
        case ePdfDataType_Reference:
        {
            if( rhs.m_Data.pData ) 
                m_Data.pData = new PdfReference( *(static_cast<PdfReference*>(rhs.m_Data.pData)) );
            break;
        }
        case ePdfDataType_Dictionary:
        {
            if( rhs.m_Data.pData ) 
                m_Data.pData = new PdfDictionary( *(static_cast<PdfDictionary*>(rhs.m_Data.pData)) );
            break;
        }
        case ePdfDataType_Name:
        {
            if( rhs.m_Data.pData ) 
                m_Data.pData = new PdfName( *(static_cast<PdfName*>(rhs.m_Data.pData)) );
            break;
        }
        case ePdfDataType_String:
        case ePdfDataType_HexString:
        {
            if( rhs.m_Data.pData ) 
                m_Data.pData = new PdfString( *(static_cast<PdfString*>(rhs.m_Data.pData)) );
            break;
        }
            
        case ePdfDataType_RawData: 
        {
            if( rhs.m_Data.pData ) 
                m_Data.pData = new PdfData( *(static_cast<PdfData*>(rhs.m_Data.pData)) );
            break;
        }
        case ePdfDataType_Bool:
        case ePdfDataType_Null:
        case ePdfDataType_Number:
        case ePdfDataType_Real:
            m_Data = rhs.m_Data;
            break;
            
        case ePdfDataType_Unknown:
        default:
            break;
    };

    SetDirty( true ); 

    return (*this);
}

const char * PdfVariant::GetDataTypeString() const
{
    switch(GetDataType())
    {
        case ePdfDataType_Bool: return "Bool";
        case ePdfDataType_Number: return "Number";
        case ePdfDataType_Real: return "Real";
        case ePdfDataType_String: return "String";
        case ePdfDataType_HexString: return "HexString";
        case ePdfDataType_Name: return "Name";
        case ePdfDataType_Array: return "Array";
        case ePdfDataType_Dictionary: return "Dictionary";
        case ePdfDataType_Null: return "Null";
        case ePdfDataType_Reference: return "Reference";
        case ePdfDataType_RawData: return "RawData";
        case ePdfDataType_Unknown: return "Unknown";
    }
    return "INVALID_TYPE_ENUM";
}

//
// This is rather slow:
//    - We set up to catch an exception
//    - We throw & catch an exception whenever there's a type mismatch
//
bool PdfVariant::operator==( const PdfVariant & rhs ) const
{
    DelayedLoad();
    try {
        switch (m_eDataType) {
            case ePdfDataType_Bool: return GetBool() == rhs.GetBool();
            case ePdfDataType_Number: return GetNumber() == rhs.GetNumber();
            case ePdfDataType_Real: return GetReal() == rhs.GetReal();
            case ePdfDataType_String: return GetString() == rhs.GetString();
            case ePdfDataType_HexString: return GetString() == rhs.GetString();
            case ePdfDataType_Name: return GetName() == rhs.GetName();
            case ePdfDataType_Array: return GetArray() == rhs.GetArray();
            case ePdfDataType_Dictionary: return GetDictionary() == rhs.GetDictionary();
            case ePdfDataType_Null: return rhs.IsNull();
            case ePdfDataType_Reference: return GetReference() == rhs.GetReference();
            case ePdfDataType_RawData: /* fall through to end of func */ break;
            case ePdfDataType_Unknown: /* fall through to end of func */ break;
        }
    }
    catch ( PdfError& e )
    {
        if (e.GetError() == ePdfError_InvalidDataType)
            return false;
        else
            throw e;
    }
    PODOFO_RAISE_ERROR_INFO( ePdfError_InvalidDataType, "Tried to compare unknown/raw variant" );
}

bool PdfVariant::IsBool() const { return GetDataType() == ePdfDataType_Bool; }
bool PdfVariant::IsNumber() const { return GetDataType() == ePdfDataType_Number; }
bool PdfVariant::IsReal() const { return GetDataType() == ePdfDataType_Real; }
bool PdfVariant::IsString() const { return GetDataType() == ePdfDataType_String; }
bool PdfVariant::IsHexString() const { return GetDataType() == ePdfDataType_HexString; }
bool PdfVariant::IsName() const { return GetDataType() == ePdfDataType_Name; }
bool PdfVariant::IsArray() const { return GetDataType() == ePdfDataType_Array; }
bool PdfVariant::IsDictionary() const { return GetDataType() == ePdfDataType_Dictionary; }
bool PdfVariant::IsRawData() const { return GetDataType() == ePdfDataType_RawData; }
bool PdfVariant::IsNull() const { return GetDataType() == ePdfDataType_Null; }
bool PdfVariant::IsReference() const { return GetDataType() == ePdfDataType_Reference; }

#if defined(PODOFO_EXTRA_CHECKS)
bool PdfVariant::DelayedLoadInProgress() const { return m_bDelayedLoadInProgress; }
#endif

void PdfVariant::DelayedLoad() const
{
#if defined(PODOFO_EXTRA_CHECKS)
    // Whoops! Delayed loading triggered during delayed loading. Someone probably
    // used a public method that calls DelayedLoad() from a delayed load.
    if (m_bDelayedLoadInProgress)
        PODOFO_RAISE_ERROR_INFO( ePdfError_InternalLogic, "Recursive DelayedLoad() detected" );
#endif
    if( !m_bDelayedLoadDone)
    {
#if defined(PODOFO_EXTRA_CHECKS)
        m_bDelayedLoadInProgress = true;
#endif
        const_cast<PdfVariant*>(this)->DelayedLoadImpl();
        // Nothing was thrown, so if the implementer of DelayedLoadImpl()
        // following the rules we're done.
        m_bDelayedLoadDone = true;
#if defined(PODOFO_EXTRA_CHECKS)
        m_bDelayedLoadInProgress = false;
#endif
    }
}

bool PdfVariant::IsEmpty() const
{
    DelayedLoad();

    return (m_eDataType == ePdfDataType_Null);
}

EPdfDataType PdfVariant::GetDataType() const
{
    DelayedLoad();

    return m_eDataType;
}

void PdfVariant::SetBool( bool b )
{
    DelayedLoad();

    if( !IsBool() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    AssertMutable();
    m_Data.bBoolValue = b;
    SetDirty( true );
}

bool PdfVariant::GetBool() const
{
    DelayedLoad();

    if( !IsBool() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    return m_Data.bBoolValue;
}

void PdfVariant::SetNumber( long l ) 
{
    DelayedLoad();

    if( !IsReal() && !IsNumber() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    AssertMutable();
    if ( IsReal() )
        m_Data.dNumber = static_cast<double>(l);
    else
        m_Data.nNumber = l;
    SetDirty( true );
}

pdf_int64 PdfVariant::GetNumber() const
{
    DelayedLoad();

    if( !IsReal() && !IsNumber() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    if ( IsReal() )
        return static_cast<long>(floor( m_Data.dNumber ));
    else
        return m_Data.nNumber;
}

void PdfVariant::SetReal( double d ) 
{
    DelayedLoad();

    if( !IsReal() && !IsNumber() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    AssertMutable();
    if ( IsReal() )
        m_Data.dNumber = d;
    else
        m_Data.nNumber = static_cast<long>(floor( d ));
    SetDirty( true );
}

double PdfVariant::GetReal() const
{
    DelayedLoad();

    if( !IsReal() && !IsNumber() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    if ( IsReal() )
        return m_Data.dNumber;
    else
        return static_cast<double>(m_Data.nNumber);
}

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif // __GNUC__
const PdfData & PdfVariant::GetRawData() const
{
    DelayedLoad();

    if( !IsRawData() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }
    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfData*)m_Data.pData);
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__


PdfData & PdfVariant::GetRawData()
{
    DelayedLoad();

    if( !IsRawData() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }
    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfData*)m_Data.pData);
}

const PdfString & PdfVariant::GetString() const
{
    DelayedLoad();

    if( !IsString() && !IsHexString() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }
    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfString*)m_Data.pData);
}

const PdfName & PdfVariant::GetName() const
{
    DelayedLoad();

    if( !IsName() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfName*)m_Data.pData);
}

const PdfArray & PdfVariant::GetArray() const
{
    DelayedLoad();
    return GetArray_NoDL();
}

const PdfArray & PdfVariant::GetArray_NoDL() const
{
    // Test against eDataType directly not GetDataType() since
    // we don't want to trigger a delayed load (and if required one has
    // already been triggered).
    if( m_eDataType != ePdfDataType_Array )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfArray*)m_Data.pData);
}

PdfArray & PdfVariant::GetArray()
{
    DelayedLoad();
    return GetArray_NoDL();
}

PdfArray & PdfVariant::GetArray_NoDL()
{
    // Test against eDataType directly not GetDataType() since
    // we don't want to trigger a delayed load (and if required one has
    // already been triggered).
    if( m_eDataType != ePdfDataType_Array )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfArray*)m_Data.pData);
}

const PdfDictionary & PdfVariant::GetDictionary() const
{
    DelayedLoad();
    return GetDictionary_NoDL();
}

const PdfDictionary & PdfVariant::GetDictionary_NoDL() const
{
    // Test against eDataType directly not GetDataType() since
    // we don't want to trigger a delayed load (and if required one has
    // already been triggered).
    if( m_eDataType != ePdfDataType_Dictionary )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfDictionary*)m_Data.pData);
}

PdfDictionary & PdfVariant::GetDictionary()
{
    DelayedLoad();
    return GetDictionary_NoDL();
}

PdfDictionary & PdfVariant::GetDictionary_NoDL()
{
    // Test against eDataType directly not GetDataType() since
    // we don't want to trigger a delayed load (and if required one has
    // already been triggered).
    if( m_eDataType != ePdfDataType_Dictionary )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfDictionary*)m_Data.pData);
}

const PdfReference & PdfVariant::GetReference() const
{
    DelayedLoad();

    if( !IsReference() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    // Do not change this to an reinterpret_cast
    // We need a c-style casts here to avoid crashes
    // because a reinterpret_cast might point to a different position.
    return *((PdfReference*)m_Data.pData);
}

bool PdfVariant::DelayedLoadDone() const
{
    return m_bDelayedLoadDone;
}

void PdfVariant::EnableDelayedLoading()
{
    m_bDelayedLoadDone = false;
}

void PdfVariant::DelayedLoadImpl()
{
    // Default implementation of virtual void DelayedLoadImpl() throws, since delayed
    // loading should not be enabled except by types that support it.
    PODOFO_RAISE_ERROR( ePdfError_InternalLogic );
}

bool PdfVariant::operator!=( const PdfVariant & rhs) const
{
    return !(*this == rhs);
}

bool PdfVariant::IsDirty() const
{
    // If this is a object with
    // stream, the streams dirty
    // flag might be set.
    if( m_bDirty )
        return m_bDirty;

    switch( m_eDataType ) 
    {
        case ePdfDataType_Array:
        case ePdfDataType_Dictionary:
            // Arrays and Dictionaries
            // handle dirty status by themselfes
            return m_Data.pData->IsDirty();

        case ePdfDataType_Bool:
        case ePdfDataType_Number:
        case ePdfDataType_Real:
        case ePdfDataType_HexString:
        case ePdfDataType_String:
        case ePdfDataType_Name:
        case ePdfDataType_RawData:
        case ePdfDataType_Reference:
        case ePdfDataType_Null:
        case ePdfDataType_Unknown:
        default:
            return m_bDirty;
    };
}

void PdfVariant::SetDirty( bool bDirty ) 
{
    m_bDirty = bDirty;

    if( !m_bDirty ) 
    {
        // Propogate new dirty state to subclasses
        switch( m_eDataType ) 
        {
            case ePdfDataType_Array:
            case ePdfDataType_Dictionary:
                // Arrays and Dictionaries
                // handle dirty status by themselfes
                m_Data.pData->SetDirty( m_bDirty );

            case ePdfDataType_Bool:
            case ePdfDataType_Number:
            case ePdfDataType_Real:
            case ePdfDataType_HexString:
            case ePdfDataType_String:
            case ePdfDataType_Name:
            case ePdfDataType_RawData:
            case ePdfDataType_Reference:
            case ePdfDataType_Null:
            case ePdfDataType_Unknown:
            default:
                break;
        };    
    }
}

void PdfVariant::SetImmutable(bool bImmutable)
{
    m_bImmutable = bImmutable;

    switch( m_eDataType ) 
    {
        case ePdfDataType_Array:
        case ePdfDataType_Dictionary:
            // Arrays and Dictionaries
            // handle dirty status by themselfes
            m_Data.pData->SetImmutable( m_bImmutable );
            
        case ePdfDataType_Bool:
        case ePdfDataType_Number:
        case ePdfDataType_Real:
        case ePdfDataType_HexString:
        case ePdfDataType_String:
        case ePdfDataType_Name:
        case ePdfDataType_RawData:
        case ePdfDataType_Reference:
        case ePdfDataType_Null:
        case ePdfDataType_Unknown:
        default:
            break;
    };    
}

bool PdfVariant::GetImmutable() const 
{
    return m_bImmutable;
}

void PdfVariant::AssertMutable() const
{
    if(m_bImmutable) 
    {
        throw new PdfError( ePdfError_ChangeOnImmutable );
    }
}

};
