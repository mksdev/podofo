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

#ifndef _PDF_REF_COUNTED_BUFFER_H_
#define _PDF_REF_COUNTED_BUFFER_H_

#include "PdfDefines.h"

namespace PoDoFo {

/** 
 * A reference counted buffer object
 * which is deleted as soon as the last
 * object having access to it is delteted.
 *
 * The attached memory object can be resized.
 */
class PODOFO_API PdfRefCountedBuffer {
 public:
    /** Created an empty reference counted buffer
     *  The buffer will be initialize to NULL
     */
    PdfRefCountedBuffer();

    /** Created an reference counted buffer and use an exiting buffer
     *  The buffer will be owned by this object.
     *
     *  \param pBuffer a pointer to an allocated buffer
     *  \param lSize   size of the allocated buffer
     *
     *  \see SetTakePossesion
     */
    PdfRefCountedBuffer( char* pBuffer, size_t lSize );

    /** Create a new PdfRefCountedBuffer. 
     *  \param lSize buffer size
     */
    PdfRefCountedBuffer( size_t lSize );

    /** Copy an existing PdfRefCountedBuffer and increase
     *  the reference count
     *  \param rhs the PdfRefCountedBuffer to copy
     */
    PdfRefCountedBuffer( const PdfRefCountedBuffer & rhs );

    /** Decrease the reference count and delete the buffer
     *  if this is the last owner
     */
    ~PdfRefCountedBuffer();
    
    /* !Non-Doxygen comment because constructor is disabled!
     *  Append to the current buffers contents. 
     *  If the buffer is referenced by another PdfRefCountedBuffer
     *  this object detaches from this buffer and allocates an own
     *  buffer. Otherwise the internal buffer is used and resized if
     *  necessary.
     *
     *  \param pszString a buffer
     *  \param lLen length of the buffer
     */
    //void Append( const char* pszString, long lLen ); 

    /** Get access to the buffer
     *  \returns the buffer
     */
    char* GetBuffer() const;

    /** Return the buffer size.
     *
     *  \returns the buffer size
     */
    size_t GetSize() const;

    /** Resize the buffer to hold at least
     *  lSize bytes.
     *
     *  \param lSize the size of bytes the buffer can at least hold
     *         
     *  If the buffer is larger no operation is performed.
     */
    void Resize( size_t lSize );

    /** Copy an existing PdfRefCountedBuffer and increase
     *  the reference count
     *  \param rhs the PdfRefCountedBuffer to copy
     *  \returns the copied object
     */
    const PdfRefCountedBuffer & operator=( const PdfRefCountedBuffer & rhs );

    /** If the PdfRefCountedBuffer has no possesion on its buffer,
     *  it won't delete the buffer. By default the buffer is owned
     *  and deleted by the PdfRefCountedBuffer object.
     *
     *  \param bTakePossession if false the buffer will not be deleted.
     */
    void SetTakePossesion( bool bTakePossession );

    /** 
     * \returns true if the buffer is owned by the PdfRefCountedBuffer
     *               and is deleted along with it.
     */
    bool TakePossesion() const;

    /** Compare to buffers.
     *  \param rhs compare to this buffer
     *  \returns true if both buffers contain the same contents
     */
    bool operator==( const PdfRefCountedBuffer & rhs ) const;

    /** Compare to buffers.
     *  \param rhs compare to this buffer
     *  \returns true if this buffer is lexically littler than rhs
     */
    bool operator<( const PdfRefCountedBuffer & rhs ) const;

    /** Compare to buffers.
     *  \param rhs compare to this buffer
     *  \returns true if this buffer is lexically greater than rhs
     */
    bool operator>( const PdfRefCountedBuffer & rhs ) const;

 private:
    /**
     * Indicate that the buffer is no longer being used, freeing it if there
     * are no further users. The buffer becomes inaccessible to this
     * PdfRefCountedBuffer in either case.
     */
    void DerefBuffer();

    /**
     * Free a buffer if the refcount is zero. Internal method used by DerefBuffer.
     */
    void FreeBuffer();

    /** Detach from a shared buffer or do nothing if we are the only 
     *  one referencing the buffer.
     *
     *  Call this function before any operation modifiying the buffer!
     *
     *  \param lLen an additional parameter specifiying extra bytes
     *              to be allocated to optimize allocations of a new buffer.
     */
    void Detach( size_t lExtraLen = 0 );

    /**
     * Called by Detach() to do the work if action is actually required.
     * \see Detach
     */
    void ReallyDetach( size_t lExtraLen );

    /**
     * Do the hard work of resizing the buffer if it turns out not to already be big enough.
     * \see Resize
     */
    void ReallyResize( size_t lSize );

 private:
    struct TRefCountedBuffer {
        enum { INTERNAL_BUFSIZE = 32 };
        // Convenience for buffer switching
        PODOFO_NOTHROW char * GetRealBuffer();
        // size in bytes of the buffer. If and only if this is strictly >INTERNAL_BUFSIZE,
        // this buffer is on the heap in memory pointed to by m_pHeapBuffer . If it is <=INTERNAL_BUFSIZE,
        // the buffer is in the in-object buffer m_sInternalBuffer.
        size_t  m_lBufferSize;
        // Size in bytes of m_pBuffer that should be reported to clients. We
        // over-allocate on the heap for efficiency and have a minimum 32 byte
        // size, but this extra should NEVER be visible to a client.
        size_t  m_lVisibleSize;
        long  m_lRefCount;
        char* m_pHeapBuffer;
        char  m_sInternalBuffer[INTERNAL_BUFSIZE];
        bool  m_bPossesion;
        // Are we using the heap-allocated buffer in place of our small internal one?
        bool  m_bOnHeap;
    };

    TRefCountedBuffer* m_pBuffer;
};

};

#endif // _PDF_REF_COUNTED_BUFFER_H_
