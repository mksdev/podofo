/***************************************************************************
 *   Copyright (C) 2007 by Dominik Seichter                                *
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

#include "PdfFileStream.h"

#include "PdfFilter.h"
#include "PdfObject.h"
#include "PdfOutputDevice.h"
#include "PdfOutputStream.h"

namespace PoDoFo {

PdfFileStream::PdfFileStream( PdfObject* pParent, PdfOutputDevice* pDevice )
    : PdfStream( pParent ), m_pDevice( pDevice ), m_pStream( NULL ), m_pDeviceStream( NULL ),
      m_lLenInitial( 0 ), m_lLength( 0 ), m_bFinalized(false)
{
    m_pLength = pParent->GetOwner()->CreateObject( PdfVariant(0L) );
    m_pParent->GetDictionary().AddKey( PdfName::KeyLength, m_pLength->Reference() );
}

PdfFileStream::~PdfFileStream() 
{
    // when we're destroyed, we won't be doing any more writing to the stream,
    // so we can safely release our lock on it.
    m_pDevice->PopWriter(this);
}

void PdfFileStream::Write( PdfOutputDevice* pDevice )
{
    PODOFO_RAISE_LOGIC_IF( pDevice != m_pDevice,
            "Tried to Write() file stream to an output device other than its own");
    // Flag ourselves as finalized, so any further attempts to modify the output
    // device will fail. Otherwise, we'd still be able to wrie to the output device
    // if nobody else had taken a lock on it.
    m_bFinalized = true;
    // and release the lock on the output device.
    m_pDevice->PopWriter(this);
}

void PdfFileStream::BeginAppendImpl( const TVecFilters & vecFilters )
{
    PODOFO_RAISE_LOGIC_IF( m_bFinalized, "Tried to append to finalized file stream" );
    // Lock the stream so nobody else can do anything with it until we're finished
    m_pDevice->PushWriter(0, this);

    m_pParent->GetOwner()->WriteObject( m_pParent );

    m_lLenInitial = m_pDevice->GetLength();

    if( vecFilters.size() )
    {
        m_pDeviceStream = new PdfDeviceOutputStream( m_pDevice );
        m_pStream       = PdfFilterFactory::CreateEncodeStream( vecFilters, m_pDeviceStream );
    }
    else 
        m_pStream = new PdfDeviceOutputStream( m_pDevice );
}

void PdfFileStream::AppendImpl( const char* pszString, size_t lLen )
{
    PODOFO_RAISE_LOGIC_IF( m_bFinalized, "Tried to append to finalized file stream" );
    m_pStream->Write( pszString, lLen );
}

void PdfFileStream::EndAppendImpl()
{
    PODOFO_RAISE_LOGIC_IF( m_bFinalized, "Tried to append to finalized file stream" );

    if( m_pStream ) 
    {
        m_pStream->Close();
        delete m_pStream;
        m_pStream = NULL;
    }

    if( m_pDeviceStream ) 
    {
        m_pDeviceStream->Close();
        delete m_pDeviceStream;
        m_pDeviceStream = NULL;
    }

    m_lLength = m_pDevice->GetLength() - m_lLenInitial;
    m_pLength->SetNumber( m_lLength );
}

void PdfFileStream::GetCopy( char**, long* ) const
{
    PODOFO_RAISE_ERROR( ePdfError_InternalLogic );
}

};

