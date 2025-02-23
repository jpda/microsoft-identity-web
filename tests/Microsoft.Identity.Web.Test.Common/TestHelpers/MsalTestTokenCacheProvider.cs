﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web.TokenCacheProviders;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;

namespace Microsoft.Identity.Web.Test.Common.TestHelpers
{
    public class MsalTestTokenCacheProvider : MsalAbstractTokenCacheProvider
    {
        public MsalTestTokenCacheProvider(
            IMemoryCache memoryCache,
            IOptions<MsalMemoryTokenCacheOptions> cacheOptions)
            : base(null)
        {
            MemoryCache = memoryCache;
            _cacheOptions = cacheOptions?.Value;
        }

        public IMemoryCache MemoryCache { get; }

        public int Count { get; internal set; }

        private readonly MsalMemoryTokenCacheOptions _cacheOptions;

        protected override Task<byte[]> ReadCacheBytesAsync(string cacheKey)
        {
            byte[] tokenCacheBytes = (byte[])MemoryCache.Get(cacheKey);
            return Task.FromResult(tokenCacheBytes);
        }

        protected override Task RemoveKeyAsync(string cacheKey)
        {
            MemoryCache.Remove(cacheKey);
            Count--;
            return Task.CompletedTask;
        }

        protected override Task WriteCacheBytesAsync(string cacheKey, byte[] bytes)
        {
            MemoryCache.Set(cacheKey, bytes, _cacheOptions.AbsoluteExpirationRelativeToNow);
            Count++;
            return Task.CompletedTask;
        }
    }
}
