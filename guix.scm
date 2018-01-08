(use-modules (ice-9 match)
             (srfi srfi-1)
             (guix gexp)
             (guix packages)
             (guix licenses)
             (guix download)
             (guix git-download)
             (guix build-system python)
             (gnu packages)
             (gnu packages base)
             (gnu packages check)
             (gnu packages python)
             (gnu packages time)
             (gnu packages python-crypto))

(define %source-dir (dirname (current-filename)))

(define python-pyld-signatures
  (package
    (name "python-pyld-signatures")
    (version "git")
    (source (local-file %source-dir
                        #:recursive? #t
                        #:select? (git-predicate %source-dir)))
    (build-system python-build-system)
    (native-inputs
     `(("python-sphinx" ,python-sphinx)))
    (propagated-inputs
     `(("python-cryptography" ,python-cryptography)
       ("python-isodate" ,python-isodate)
       ("python-pyld" ,python-pyld)
       ("python-pytz" ,python-pytz)
       ("python-pytest" ,python-pytest)))
    (home-page "https://github.com/Spec-Ops/pyld-signatures/")
    (synopsis "Implementation of Linked Data Signatures using python-pyld.")
    (description "python-pyld-signatures is a Python library implementing
the Linked Data Signatures algorithm, for verifiable claims and other purposes.
It builds on python-pyld and integrates nicely with existing json-ld applications.")
    (license bsd-3)))

;; Make sure we have Python in our environment
(package
  (inherit python-pyld-signatures)
  (inputs
   `(("python" ,python))))
