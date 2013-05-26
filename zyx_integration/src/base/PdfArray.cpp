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

#include "PdfArray.h"

#include "PdfOutputDevice.h"
#include "PdfDefinesPrivate.h"

#include <limits>

namespace PoDoFo {

PdfArray::PdfArray()
    : PdfArrayBaseClass(), PdfDataType(), m_bDirty( false )
{
}

PdfArray::~PdfArray()
{
}

PdfArray::PdfArray( const PdfObject & var )
    : PdfArrayBaseClass(), PdfDataType(), m_bDirty( false )
{
    this->push_back( var );
}

PdfArray::PdfArray( const PdfArray & rhs )
    : PdfArrayBaseClass(rhs), PdfDataType(rhs), m_bDirty(rhs.m_bDirty)
{
    this->operator=( rhs );
}

 
PdfArray& PdfArray::operator=(const PdfArray& rhs)
{
    if (this != &rhs)
    {
        m_bDirty = rhs.m_bDirty;
        PdfArrayBaseClass::operator=( rhs );
    }
    else
    {
        //do nothing
    }
    
    return *this;
}

void PdfArray::Write( PdfOutputDevice* pDevice, EPdfWriteMode eWriteMode, 
                      const PdfEncrypt* pEncrypt ) const
{
    PdfArray::const_iterator it = this->begin();

    int count = 1;

    if( (eWriteMode & ePdfWriteMode_Clean) == ePdfWriteMode_Clean ) 
    {
        pDevice->Print( "[ " );
    }
    else
    {
        pDevice->Print( "[" );
    }

    while( it != this->end() )
    {
        (*it).Write( pDevice, eWriteMode, pEncrypt );
        if( (eWriteMode & ePdfWriteMode_Clean) == ePdfWriteMode_Clean ) 
        {
            pDevice->Print( (count % 10 == 0) ? "\n" : " " );
        }

        ++it;
        ++count;
    }

    pDevice->Print( "]" );
}

bool PdfArray::ContainsString( const std::string& cmpString ) const
{
    bool foundIt = false;

    TCIVariantList it(this->begin());
    while( it != this->end() )
    {
        if( (*it).GetDataType() == ePdfDataType_String )
        {
            if ( (*it).GetString().GetString() == cmpString ) {
                foundIt = true;
                break;
            }
        }
        
        ++it;
    }
    
    return foundIt;
}

size_t PdfArray::GetStringIndex( const std::string& cmpString ) const
{
    size_t foundIdx = std::numeric_limits<size_t>::max();
    
    for ( size_t i=0; i<this->size(); i++ ) {
        if( (*this)[i].GetDataType() == ePdfDataType_String )
        {
            if ( (*this)[i].GetString().GetString() == cmpString ) 
            {
                foundIdx = i;
                break;
            }
        }
    }
    
    return foundIdx;
}

bool PdfArray::IsDirty() const
{
    // If the array itself is dirty
    // return immediately
    // otherwise check all children.
    if( m_bDirty )
        return m_bDirty;

    PdfArray::const_iterator it(this->begin());
    while( it != this->end() )
    {
        if( (*it).IsDirty() )
            return true;

        ++it;
    }

    return false;
}

void PdfArray::SetDirty( bool bDirty )
{
    m_bDirty = bDirty;

    if( !m_bDirty )
    {
        // Propagate state to all subclasses
        PdfArray::iterator it(this->begin());
        while( it != this->end() )
        {
            (*it).SetDirty( m_bDirty );
            ++it;
        }
    }
}

void PdfArray::Clear() 
{
    AssertMutable();

    this->clear();
}

size_t PdfArray::GetSize() const
{
    return this->size();
}

void PdfArray::push_back( const PdfObject & var )
{
    AssertMutable();

    PdfArrayBaseClass::push_back( var );
    m_bDirty = true;
}

size_t PdfArray::size() const
{
    return PdfArrayBaseClass::size();
}

bool PdfArray::empty() const
{
    return PdfArrayBaseClass::empty();
}

PdfObject& PdfArray::operator[](size_type __n)
{
    AssertMutable();

    m_bDirty = true;
    return PdfArrayBaseClass::operator[](__n);
}

const PdfObject& PdfArray::operator[](size_type __n) const
{
    return PdfArrayBaseClass::operator[](__n);
}

void PdfArray::resize(size_t __n, value_type __x)
{
    PdfArrayBaseClass::resize(__n, __x);
}

PdfArray::iterator PdfArray::begin()
{
    return PdfArrayBaseClass::begin();
}

PdfArray::const_iterator PdfArray::begin() const
{
    return PdfArrayBaseClass::begin();
}

PdfArray::iterator PdfArray::end()
{
    return PdfArrayBaseClass::end();
}

PdfArray::const_iterator PdfArray::end() const
{
    return PdfArrayBaseClass::end();
}

PdfArray::reverse_iterator PdfArray::rbegin()
{
    return PdfArrayBaseClass::rbegin();
}

PdfArray::const_reverse_iterator PdfArray::rbegin() const
{
    return PdfArrayBaseClass::rbegin();
}

PdfArray::reverse_iterator PdfArray::rend()
{
    return PdfArrayBaseClass::rend();
}

PdfArray::const_reverse_iterator PdfArray::rend() const
{
    return PdfArrayBaseClass::rend();
}

void PdfArray::insert(PdfArray::iterator __position, 
                      PdfArray::iterator __first,
                      PdfArray::iterator __last)
{
    AssertMutable();

    PdfArrayBaseClass::insert( __position, __first, __last );
    m_bDirty = true;
}

PdfArray::iterator PdfArray::insert(const iterator& __position, const PdfObject & val )
{
    AssertMutable();

    m_bDirty = true;
    return PdfArrayBaseClass::insert( __position, val );
}

void PdfArray::erase( const iterator& pos )
{
    AssertMutable();

    PdfArrayBaseClass::erase( pos );
    m_bDirty = true;
}

void PdfArray::erase( const iterator& first, const iterator& last )
{
    AssertMutable();

    PdfArrayBaseClass::erase( first, last );
    m_bDirty = true;
}

void PdfArray::reserve(size_type __n)
{
    PdfArrayBaseClass::reserve( __n );
}

PdfObject & PdfArray::front()
{
    return PdfArrayBaseClass::front();
}

const PdfObject & PdfArray::front() const
{
    return PdfArrayBaseClass::front();
}

PdfObject & PdfArray::back()
{
    return PdfArrayBaseClass::back();
}
      
const PdfObject & PdfArray::back() const
{
    return PdfArrayBaseClass::back();
}

bool PdfArray::operator==( const PdfArray & rhs ) const
{
    //TODO: This operator does not check for m_bDirty. Add comparison or add explanation why it should not be there
    return (static_cast< PdfArrayBaseClass >(*this) == static_cast< PdfArrayBaseClass >(rhs) );
}

bool PdfArray::operator!=( const PdfArray & rhs ) const
{
    //TODO: This operator does not check for m_bDirty. Add comparison or add explanation why it should not be there
    return (static_cast< PdfArrayBaseClass >(*this) != static_cast< PdfArrayBaseClass >(rhs) );
}

};
