;; Title: pyth-pnau-decoder
;; Version: v2
;; Check for latest version: https://github.com/Trust-Machines/stacks-pyth-bridge#latest-version
;; Report an issue: https://github.com/Trust-Machines/stacks-pyth-bridge/issues

;;;; Traits
(impl-trait .pyth-traits-v1.decoder-trait)
(use-trait wormhole-core-trait .wormhole-traits-v1.core-trait)

;;;; Constants

(define-constant PNAU_MAGIC 0x504e4155) ;; 'PNAU': Pyth Network Accumulator Update
(define-constant AUWV_MAGIC 0x41555756) ;; 'AUWV': Accumulator Update Wormhole Verification
(define-constant PYTHNET_MAJOR_VERSION u1)
(define-constant PYTHNET_MINOR_VERSION u0)
(define-constant UPDATE_TYPE_WORMHOLE_MERKLE u0)
(define-constant MESSAGE_TYPE_PRICE_FEED u0)
(define-constant MERKLE_PROOF_HASH_SIZE u20)

;; Unable to price feed magic bytes
(define-constant ERR_MAGIC_BYTES (err u2001))
;; Unable to parse major version
(define-constant ERR_VERSION_MAJ (err u2002))
;; Unable to parse minor version
(define-constant ERR_VERSION_MIN (err u2003))
;; Unable to parse trailing header size
(define-constant ERR_HEADER_TRAILING_SIZE (err u2004))
;; Unable to parse proof type
(define-constant ERR_PROOF_TYPE (err u2005))
;; Unable to parse update type
(define-constant ERR_UPDATE_TYPE (err u2006))
;; Merkle root mismatch
(define-constant ERR_INVALID_AUWV (err u2007))
;; Merkle root mismatch
(define-constant ERR_MERKLE_ROOT_MISMATCH (err u2008))
;; Incorrect AUWV payload
(define-constant ERR_INCORRECT_AUWV_PAYLOAD (err u2009))
;; Price update not signed by an authorized source 
(define-constant ERR_UNAUTHORIZED_PRICE_UPDATE (err u2401))
;; VAA buffer has unused, extra leading bytes (overlay)
(define-constant ERR_OVERLAY_PRESENT (err u2402))

;;;; Public functions
(define-public (decode-and-verify-price-feeds (pnau-bytes (buff 8192)) (wormhole-core-address <wormhole-core-trait>))
  (begin
    ;; Check execution flow
    (try! (contract-call? .pyth-governance-v2 check-execution-flow contract-caller none))
    ;; Proceed to update
    (decode-pnau-price-update pnau-bytes wormhole-core-address)))

;;;; Private functions
;; #[filter(pnau-bytes, wormhole-core-address)]
(define-private (decode-pnau-price-update (pnau-bytes (buff 8192)) (wormhole-core-address <wormhole-core-trait>))
  (let ((cursor-pnau-header (try! (parse-pnau-header pnau-bytes)))
        (cursor-pnau-vaa-size (try! (read-uint-16 (get next cursor-pnau-header))))
        (cursor-pnau-vaa (try! (read-buff-8192-max (get next cursor-pnau-vaa-size) (some (get value cursor-pnau-vaa-size)))))
        (vaa (try! (contract-call? wormhole-core-address parse-and-verify-vaa (get value cursor-pnau-vaa))))
        (cursor-merkle-root-data (try! (parse-merkle-root-data-from-vaa-payload (get payload vaa))))
        (decoded-prices-updates (try! (parse-and-verify-prices-updates 
          (slice (get next cursor-pnau-vaa) none)
          (get merkle-root-hash (get value cursor-merkle-root-data)))))
        (prices-updates (map cast-decoded-price decoded-prices-updates))
        (authorized-prices-data-sources (contract-call? .pyth-governance-v2 get-authorized-prices-data-sources)))
    ;; Ensure that update was published by an data source authorized by governance
    (unwrap! (index-of? 
        authorized-prices-data-sources 
        { emitter-chain: (get emitter-chain vaa), emitter-address: (get emitter-address vaa) }) 
      ERR_UNAUTHORIZED_PRICE_UPDATE)
    (ok prices-updates)))

(define-private (parse-merkle-root-data-from-vaa-payload (payload-vaa-bytes (buff 8192)))
  (let ((cursor-payload-type (unwrap! (read-buff-4 { bytes: payload-vaa-bytes, pos: u0 }) 
          ERR_INVALID_AUWV))
        (cursor-wh-update-type (unwrap! (read-uint-8 (get next cursor-payload-type)) 
          ERR_INVALID_AUWV))
        (cursor-merkle-root-slot (unwrap! (read-uint-64 (get next cursor-wh-update-type)) 
          ERR_INVALID_AUWV))
        (cursor-merkle-root-ring-size (unwrap! (read-uint-32 (get next cursor-merkle-root-slot)) 
          ERR_INVALID_AUWV))
        (cursor-merkle-root-hash (unwrap! (read-buff-20 (get next cursor-merkle-root-ring-size)) 
          ERR_INVALID_AUWV)))
    ;; Check payload type
    (asserts! (is-eq (get value cursor-payload-type) AUWV_MAGIC) ERR_MAGIC_BYTES)
    ;; Check update type
    (asserts! (is-eq (get value cursor-wh-update-type) UPDATE_TYPE_WORMHOLE_MERKLE) ERR_PROOF_TYPE)
    (ok {
      value: {
        merkle-root-slot: (get value cursor-merkle-root-slot),
        merkle-root-ring-size: (get value cursor-merkle-root-ring-size),
        merkle-root-hash: (get value cursor-merkle-root-hash),
        payload-type: (get value cursor-payload-type)
      },
      next: (get next cursor-merkle-root-hash)
    })))

(define-private (parse-pnau-header (pf-bytes (buff 8192)))
  (let ((cursor-magic (unwrap! (read-buff-4 { bytes: pf-bytes, pos: u0 }) 
          ERR_MAGIC_BYTES))
        (cursor-version-maj (unwrap! (read-uint-8 (get next cursor-magic)) 
          ERR_VERSION_MAJ))
        (cursor-version-min (unwrap! (read-uint-8 (get next cursor-version-maj)) 
          ERR_VERSION_MIN))
        (cursor-header-trailing-size (unwrap! (read-uint-8 (get next cursor-version-min)) 
          ERR_HEADER_TRAILING_SIZE))
        (cursor-proof-type (unwrap! (read-uint-8 {
            bytes: pf-bytes,
            pos: (+ (get pos (get next cursor-header-trailing-size)) (get value cursor-header-trailing-size))})
          ERR_PROOF_TYPE)))
    ;; Check magic bytes
    (asserts! (is-eq (get value cursor-magic) PNAU_MAGIC) ERR_MAGIC_BYTES)
    ;; Check major version
    (asserts! (is-eq (get value cursor-version-maj) PYTHNET_MAJOR_VERSION) ERR_VERSION_MAJ)
    ;; Check minor version
    (asserts! (>= (get value cursor-version-min) PYTHNET_MINOR_VERSION) ERR_VERSION_MIN)
    ;; Check proof type
    (asserts! (is-eq (get value cursor-proof-type) UPDATE_TYPE_WORMHOLE_MERKLE) ERR_PROOF_TYPE)
    (ok {
      value: {
        magic: (get value cursor-magic),
        version-maj: (get value cursor-version-maj),
        version-min: (get value cursor-version-min),
        header-trailing-size: (get value cursor-header-trailing-size),
        proof-type: (get value cursor-proof-type)
      },
      next: (get next cursor-proof-type)
    })))

(define-read-only (parse-and-verify-prices-updates (bytes (buff 8192)) (merkle-root-hash (buff 20)))
  (let (
        (num-updates (try! (read-uint-8? bytes u0)))
        (updates (try! (parse-price-info-and-proof2 bytes)))
        (merkle-proof-checks-success (get result (fold check-merkle-proof updates {
          result: true,
          merkle-root-hash: merkle-root-hash
        }))))
    (asserts! merkle-proof-checks-success ERR_MERKLE_ROOT_MISMATCH)
    (asserts! (is-eq num-updates (len updates)) ERR_INCORRECT_AUWV_PAYLOAD)
    ;; Overlay check; 1 is added because 1 byte is used to store "cursor-num-updates"
    (asserts! (is-eq (+ (fold sum-message-length updates u0) u1) (len bytes)) ERR_OVERLAY_PRESENT)
    (ok updates)))

;; wasteful function
(define-read-only (message-length (update {
    price-identifier: (buff 32),
    price: int,
    conf: uint,
    expo: int,
    publish-time: uint,
    prev-publish-time: uint,
    ema-price: int,
    ema-conf: uint,
    proof: (list 128 (buff 20)),
    leaf-bytes: (buff 255)
  }))
  (+ u3 (len (get leaf-bytes update)) (* (len (get proof update)) MERKLE_PROOF_HASH_SIZE))
)

;; wasteful function
(define-read-only (sum-message-length (update {
    price-identifier: (buff 32),
    price: int,
    conf: uint,
    expo: int,
    publish-time: uint,
    prev-publish-time: uint,
    ema-price: int,
    ema-conf: uint,
    proof: (list 128 (buff 20)),
    leaf-bytes: (buff 255)
  }) (a uint))
  (+ (message-length update) a)
)

(define-private (parse-price-info-and-proof2 (bytes (buff 8192)))
  (let (
    (num-updates (try! (read-uint-8? bytes u0)))
    (offset u1)
    (update1 (try! (read-and-verify-update bytes offset)))
    (update2 (unwrap! (read-and-verify-update bytes (+ (message-length update1) offset)) (ok (list update1))))
    (update3 (unwrap! (read-and-verify-update bytes (+ (message-length update1) (message-length update2) offset)) (ok (list update1 update2))))
    (update4 (unwrap! (read-and-verify-update bytes (+ (message-length update1) (message-length update2) (message-length update3) offset)) (ok (list update1 update2 update3))))
  )
    (ok (list update1 update2 update3 update4))
  )
)

(define-private (read-and-verify-update (bytes (buff 8192)) (offset uint))
  (let (
    (message-size (try! (read-uint-16? bytes offset)))
    (message-type (try! (read-uint-8? bytes (+ offset u2))))
    (price-identifier (try! (read-buff-32? bytes (+ offset u2 u1))))
    (price (try! (read-int-64? bytes (+ offset u2 u1 u32))))
    (conf (try! (read-uint-64? bytes (+ offset u2 u1 u32 u8))))
    (expo (try! (read-int-32? bytes (+ offset u2 u1 u32 u8 u8))))
    (publish-time (try! (read-uint-64? bytes (+ offset u2 u1 u32 u8 u8 u4))))
    (prev-publish-time (try! (read-uint-64? bytes (+ offset u2 u1 u32 u8 u8 u4 u8))))
    (ema-price (try! (read-int-64? bytes (+ offset u2 u1 u32 u8 u8 u4 u8 u8))))
    (ema-conf (try! (read-uint-64? bytes (+ offset u2 u1 u32 u8 u8 u4 u8 u8 u8))))
    (proof-size (try! (read-uint-8? bytes (+ offset u2 message-size))))
    (proof-bytes (unwrap! (slice? bytes
      (+ offset u2 message-size u1)
      (+ offset u2 message-size u1 (* MERKLE_PROOF_HASH_SIZE proof-size))
    ) (err u9010)))
    (leaf-bytes (unwrap! (slice? bytes (+ offset u2) (+ offset u2 message-size)) (err u9011)))
    (proof (get result (fold parse-proof proof-bytes { 
          result: (list),
          cursor: {
            index: u0,
            next-update-index: u0
          },
          bytes: proof-bytes,
          limit: proof-size
        })))
  )
  (asserts! (is-eq message-type MESSAGE_TYPE_PRICE_FEED) ERR_UPDATE_TYPE)
  (ok {
    price-identifier: price-identifier,
    price: price,
    conf: conf,
    expo: expo,
    publish-time: publish-time,
    prev-publish-time: prev-publish-time,
    ema-price: ema-price,
    ema-conf: ema-conf,
    proof: proof,
    leaf-bytes: (unwrap! (as-max-len? leaf-bytes u255) (err u9012))
  })
))

(define-private (check-merkle-proof
      (entry 
        {
          price-identifier: (buff 32),
          price: int,
          conf: uint,
          expo: int,
          publish-time: uint,
          prev-publish-time: uint,
          ema-price: int,
          ema-conf: uint,
          proof: (list 128 (buff 20)),
          leaf-bytes: (buff 255)
        })
      (acc 
        { 
          merkle-root-hash: (buff 20),
          result: bool, 
        }))
    { 
      merkle-root-hash: (get merkle-root-hash acc),
      result: (and (get result acc)
        (contract-call? 'SP2J933XB2CP2JQ1A4FGN8JA968BBG3NK3EKZ7Q9F.hk-merkle-tree-keccak160-v1 check-proof 
          (get merkle-root-hash acc) 
          (get leaf-bytes entry) 
          (get proof entry)))
    })

(define-private (parse-proof
      (entry (buff 1)) 
      (acc { 
        cursor: { 
          index: uint,
          next-update-index: uint
        },
        bytes: (buff 8192),
        result: (list 128 (buff 20)), 
        limit: uint
      }))
  (if (is-eq (len (get result acc)) (get limit acc))
    acc
    (if (is-eq (get index (get cursor acc)) (get next-update-index (get cursor acc)))
      ;; Parse update
      (let ((cursor-hash (new (get bytes acc) (some (get index (get cursor acc)))))
            (hash (get value (unwrap-panic (read-buff-20 (get next cursor-hash))))))
        {
          cursor: { 
            index: (+ (get index (get cursor acc)) u1),
            next-update-index: (+ (get index (get cursor acc)) MERKLE_PROOF_HASH_SIZE),
          },
          bytes: (get bytes acc),
          result: (unwrap-panic (as-max-len? (append (get result acc) hash) u128)),
          limit: (get limit acc),
        })
      ;; Increment position
      {
          cursor: { 
            index: (+ (get index (get cursor acc)) u1),
            next-update-index: (get next-update-index (get cursor acc)),
          },
          bytes: (get bytes acc),
          result: (get result acc),
          limit: (get limit acc)
      })))

(define-private (cast-decoded-price (entry 
        {
          price-identifier: (buff 32),
          price: int,
          conf: uint,
          expo: int,
          publish-time: uint,
          prev-publish-time: uint,
          ema-price: int,
          ema-conf: uint,
          proof: (list 128 (buff 20)),
          leaf-bytes: (buff 255)
        }))
  {
    price-identifier: (get price-identifier entry),
    price: (get price entry),
    conf: (get conf entry),
    expo: (get expo entry),
    publish-time: (get publish-time entry),
    prev-publish-time: (get prev-publish-time entry),
    ema-price: (get ema-price entry),
    ema-conf: (get ema-conf entry)
  })

(define-read-only (read-buff-1 (cursor { bytes: (buff 8192), pos: uint }))
    (ok { 
        value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) (get pos cursor) (+ (get pos cursor) u1)) (err u1)) u1) (err u1)), 
        next: { bytes: (get bytes cursor), pos: (+ (get pos cursor) u1) }
    }))

(define-read-only (read-buff-2 (cursor { bytes: (buff 8192), pos: uint }))
    (ok { 
        value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) (get pos cursor) (+ (get pos cursor) u2)) (err u1)) u2) (err u1)), 
        next: { bytes: (get bytes cursor), pos: (+ (get pos cursor) u2) }
    }))

(define-read-only (read-buff-4 (cursor { bytes: (buff 8192), pos: uint }))
    (ok { 
        value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) (get pos cursor) (+ (get pos cursor) u4)) (err u1)) u4) (err u1)), 
        next: { bytes: (get bytes cursor), pos: (+ (get pos cursor) u4) }
    }))

(define-read-only (read-buff-8 (cursor { bytes: (buff 8192), pos: uint }))
    (ok { 
        value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) (get pos cursor) (+ (get pos cursor) u8)) (err u1)) u8) (err u1)), 
        next: { bytes: (get bytes cursor), pos: (+ (get pos cursor) u8) }
    }))

(define-read-only (read-buff-16 (cursor { bytes: (buff 8192), pos: uint }))
    (ok { 
        value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) (get pos cursor) (+ (get pos cursor) u16)) (err u1)) u16) (err u1)), 
        next: { bytes: (get bytes cursor), pos: (+ (get pos cursor) u16) }
    }))

(define-read-only (read-buff-20 (cursor { bytes: (buff 8192), pos: uint }))
    (ok { 
        value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) (get pos cursor) (+ (get pos cursor) u20)) (err u1)) u20) (err u1)), 
        next: { bytes: (get bytes cursor), pos: (+ (get pos cursor) u20) }
    }))

(define-read-only (read-buff-8192-max (cursor { bytes: (buff 8192), pos: uint }) (size (optional uint)))
    (let ((min (get pos cursor))
          (max (match size value 
            (+ value (get pos cursor))
            (len (get bytes cursor)))))
      (ok { 
          value: (unwrap! (as-max-len? (unwrap! (slice? (get bytes cursor) min max) (err u1)) u8192) (err u1)), 
          next: { bytes: (get bytes cursor), pos: max }
      })))

(define-read-only (read-uint-8 (cursor { bytes: (buff 8192), pos: uint }))
    (let ((cursor-bytes (try! (read-buff-1 cursor))))
        (ok (merge cursor-bytes { value: (buff-to-uint-be (get value cursor-bytes)) }))))

(define-read-only (read-uint-16 (cursor { bytes: (buff 8192), pos: uint }))
    (let ((cursor-bytes (try! (read-buff-2 cursor))))
        (ok (merge cursor-bytes { value: (buff-to-uint-be (get value cursor-bytes)) }))))

(define-read-only (read-uint-32 (cursor { bytes: (buff 8192), pos: uint }))
    (let ((cursor-bytes (try! (read-buff-4 cursor))))
        (ok (merge cursor-bytes { value: (buff-to-uint-be (get value cursor-bytes)) }))))

(define-read-only (read-uint-64 (cursor { bytes: (buff 8192), pos: uint }))
    (let ((cursor-bytes (try! (read-buff-8 cursor))))
        (ok (merge cursor-bytes { value: (buff-to-uint-be (get value cursor-bytes)) }))))

(define-read-only (read-int-32 (cursor { bytes: (buff 8192), pos: uint }))
    (let ((cursor-bytes (try! (read-buff-4 cursor))))
        (ok (merge 
            cursor-bytes 
            { value: (bit-shift-right (bit-shift-left (buff-to-int-be (get value cursor-bytes)) u96) u96) }))))

(define-read-only (new (bytes (buff 8192)) (offset (optional uint)))
    { 
        value: none, 
        next: { bytes: bytes, pos: (match offset value value u0) }
    })

(define-read-only (slice (cursor { bytes: (buff 8192), pos: uint }) (size (optional uint)))
    (match (slice? (get bytes cursor) 
                   (get pos cursor) 
                   (match size value 
                   (+ (get pos cursor) value)    
                      (len (get bytes cursor))))
        bytes bytes 0x))

(define-read-only (read-uint-8? (buffer (buff 8192)) (offset uint))
  (ok (buff-to-uint-be (unwrap! (as-max-len? (unwrap! (slice? buffer offset (+ offset u1)) (err u9000)) u1) (err u9000))))
)

(define-read-only (read-uint-16? (buffer (buff 8192)) (offset uint))
  (ok (buff-to-uint-be (unwrap! (as-max-len? (unwrap! (slice? buffer offset (+ offset u2)) (err u9001)) u2) (err u9001))))
)

(define-read-only (read-uint-64? (buffer (buff 8192)) (offset uint))
  (ok (buff-to-uint-be (unwrap! (as-max-len? (unwrap! (slice? buffer offset (+ offset u8)) (err u9002)) u8) (err u9002))))
)

(define-read-only (read-int-32? (buffer (buff 8192)) (offset uint))
  (ok (bit-shift-right (bit-shift-left (buff-to-int-be (unwrap! (as-max-len? (unwrap! (slice? buffer offset (+ offset u4)) (err u9003)) u4) (err u9003))) u96) u96))
)

(define-read-only (read-int-64? (buffer (buff 8192)) (offset uint))
  (ok (bit-shift-right (bit-shift-left (buff-to-int-be (unwrap! (as-max-len? (unwrap! (slice? buffer offset (+ offset u8)) (err u9004)) u8) (err u9004))) u64) u64))
)

(define-read-only (read-buff-32? (buffer (buff 8192)) (offset uint))
  (ok (unwrap! (as-max-len? (unwrap! (slice? buffer offset (+ offset u32)) (err u9005)) u32) (err u9005)))
)

