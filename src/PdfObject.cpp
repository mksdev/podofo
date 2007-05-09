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

#include "PdfObject.h"

#include "PdfArray.h"
#include "PdfDictionary.h"
#include "PdfOutputDevice.h"
#include "PdfStream.h"
#include "PdfVariant.h"

#include <sstream>
#include <fstream>
#include <cassert>

#include <string.h>

using namespace std;

namespace PoDoFo {

PdfObject::PdfObject()
    : PdfVariant( PdfDictionary() )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfReference & rRef, const char* pszType )
    : PdfVariant( PdfDictionary() ), m_reference( rRef )
{
    InitPdfObject();

    if( pszType )
        this->GetDictionary().AddKey( PdfName::KeyType, PdfName( pszType ) );
}

PdfObject::PdfObject( const PdfReference & rRef, const PdfVariant & rVariant )
    : PdfVariant( rVariant ), m_reference( rRef )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfVariant & var )
    : PdfVariant( var )
{
    InitPdfObject();
}

PdfObject::PdfObject( bool b )
    : PdfVariant( b )
{
    InitPdfObject();
}

PdfObject::PdfObject( long l )
    : PdfVariant( l )
{
    InitPdfObject();
}

PdfObject::PdfObject( double d )
    : PdfVariant( d )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfString & rsString )
    : PdfVariant( rsString )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfName & rName )
    : PdfVariant( rName )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfReference & rRef )
    : PdfVariant( rRef )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfArray & tList )
    : PdfVariant( tList )
{
    InitPdfObject();
}

PdfObject::PdfObject( const PdfDictionary & rDict )
    : PdfVariant( rDict )
{
    InitPdfObject();
}

PdfObject::~PdfObject()
{
    delete m_pStream;
    m_pStream = NULL;
}

void PdfObject::InitPdfObject()
{
    m_pStream                 = NULL;
    m_pOwner                = NULL;

    m_bDelayedStreamLoadDone  = true;

#if defined(PODOFO_EXTRA_CHECKS)
    m_bDelayedStreamLoadInProgress = false;
#endif
}

void PdfObject::Write( PdfOutputDevice* pDevice ) const
{
    Write(pDevice, PdfName::KeyNull);
}

void PdfObject::Write( PdfOutputDevice* pDevice, const PdfName & keyStop ) const
{
    DelayedStreamLoad();

    if( !pDevice )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    if( m_reference.IsIndirect() )
        pDevice->Print( "%i %i obj\n", m_reference.ObjectNumber(), m_reference.GenerationNumber() );

    PdfVariant::Write( pDevice, keyStop );
    pDevice->Print( "\n" );

    if( m_pStream )
        m_pStream->Write( pDevice );

    if( m_reference.IsIndirect() )
        pDevice->Print( "endobj\n" );
}

PdfVariant* PdfObject::GetIndirectKey( const PdfName & key )
{
    PdfVariant* pVar = NULL;

    if( this->IsDictionary() && this->GetDictionary().HasKey( key ) )
    {
        pVar = this->GetDictionary().GetKey( key );
        if( pVar->IsReference() ) 
        {
            if( !m_pOwner )
            {
                PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
            }
            pVar = m_pOwner->GetObject( pVar->GetReference() );
        }
        /* XXX TODO indirects can no longer have an owner. Do we rely on this anywhere?
        else
            pVar->SetOwner( GetOwner() );// even directs might want an owner...
        */
    }

    return pVar;
}

unsigned long PdfObject::GetObjectLength()
{
    PdfOutputDevice device;

    this->Write( &device );

    return device.GetLength();
}

PdfStream* PdfObject::GetStream()
{
    DelayedStreamLoad();
    return GetStream_NoDL();
}

PdfStream* PdfObject::GetStream_NoDL()
{
    if( !m_pStream )
    {
        if( !m_pOwner ) 
        {
            PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
        }

        m_pStream = m_pOwner->CreateStream( this );
    }

    return m_pStream;
}

const PdfStream* PdfObject::GetStream() const
{
    DelayedStreamLoad();

    return m_pStream;
}

void PdfObject::FlateCompressStream() 
{
    // TODO: If the stream isn't already in memory, defer loading and compression until first read of the stream to save some memory.
    DelayedStreamLoad();

    /*
    if( m_pStream )
        m_pStream->FlateCompress();
    */
}

};
