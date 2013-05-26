/***************************************************************************
 *   Copyright (C) 2006 by Dominik Seichter                                *
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

#include "PdfReference.h"

#include "PdfOutputDevice.h"
#include "PdfDefinesPrivate.h"

#include <sstream>

namespace PoDoFo {

PdfReference::PdfReference()
	: m_nObjectNo( 0 ), m_nGenerationNo( 0 )
{
}

PdfReference::PdfReference( const pdf_objnum nObjectNo, const pdf_gennum nGenerationNo )
  : m_nObjectNo( nObjectNo ), m_nGenerationNo( nGenerationNo ) 
{
}

PdfReference::PdfReference( const PdfReference & rhs ) : PdfDataType()
{
  this->operator=( rhs );
}

PdfReference::~PdfReference() { }

void PdfReference::Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, const PdfEncrypt* ) const
{
    if( (eWriteMode & ePdfWriteMode_Compact) == ePdfWriteMode_Compact ) 
    {
        // Write space before the reference
        pDevice->Print( " %i %hi R", m_nObjectNo, m_nGenerationNo );
    }
    else
    {
        pDevice->Print( "%i %hi R", m_nObjectNo, m_nGenerationNo );
    }
}

const std::string PdfReference::ToString() const
{
    std::ostringstream out;
    out << m_nObjectNo << " " << m_nGenerationNo << " R";
    return out.str();
}

const PdfReference & PdfReference::operator=( const PdfReference & rhs )
{
    m_nObjectNo     = rhs.m_nObjectNo;
    m_nGenerationNo = rhs.m_nGenerationNo;
    return *this;
}

bool PdfReference::operator<( const PdfReference & rhs ) const
{
    return m_nObjectNo == rhs.m_nObjectNo ? m_nGenerationNo < rhs.m_nGenerationNo : m_nObjectNo < rhs.m_nObjectNo;
}

bool PdfReference::operator==( const PdfReference & rhs ) const
{
    return ( m_nObjectNo == rhs.m_nObjectNo && m_nGenerationNo == rhs.m_nGenerationNo);
}

bool PdfReference::operator!=( const PdfReference & rhs ) const
{
    return !this->operator==( rhs );
}

void PdfReference::SetObjectNumber( pdf_objnum o )
{
    m_nObjectNo = o;
}

pdf_objnum PdfReference::ObjectNumber() const
{
    return m_nObjectNo;
}

void PdfReference::SetGenerationNumber( pdf_gennum g )
{
    m_nGenerationNo = g;
}

pdf_gennum PdfReference::GenerationNumber() const
{
    return m_nGenerationNo;
}

bool PdfReference::IsIndirect() const
{
    return !( !m_nObjectNo && !m_nGenerationNo );
}

};
