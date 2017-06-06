package cmd

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
)

// Options represents the parameters for creating a new middleware
type Options struct {
	SP                saml.ServiceProvider
	AllowIDPInitiated bool
	IDPMetadata       *saml.EntityDescriptor
	IDPMetadataURL    url.URL
	HTTPClient        *http.Client
}

// New creates a new SAMLMiddleware
func New(opts Options) (*SAMLMiddleware, error) {
	m := &SAMLMiddleware{
		ServiceProvider:   opts.SP,
		AllowIDPInitiated: opts.AllowIDPInitiated,
		CookieName:        defaultCookieName,
		CookieMaxAge:      defaultCookieMaxAge,
	}

	c := opts.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}

	req, err := http.NewRequest("GET", opts.IDPMetadataURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Some providers (like OneLogin) do not work properly unless the User-Agent header is specified.
	// Setting the user agent prevents the 403 Forbidden errors.
	req.Header.Set("User-Agent", globalServerUserAgent)

	// Done channel is used to close any lingering retry routine, as soon
	// as this function returns.
	doneCh := make(chan struct{})

	// Indicate to our retry routine to exit cleanly, upon this function return.
	defer close(doneCh)

	// Wait on the jitter retry loop.
	retryTimerCh := newRetryTimerSimple(doneCh)
	for {
		select {
		case retryCount := <-retryTimerCh:
			resp, err := c.Do(req)
			if err != nil {
				if retryCount > 10 {
					return nil, err
				}
				continue
			}
			if resp.StatusCode != http.StatusOK {
				if retryCount > maxRetryAttempts {
					return nil, fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
				}
				continue
			}
			data, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				if retryCount > maxRetryAttempts {
					return nil, err
				}
				continue
			}

			entity := &saml.EntityDescriptor{}
			err = xml.Unmarshal(data, entity)
			// this comparison is ugly, but it is how the error is generated in encoding/xml
			if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
				entities := &saml.EntitiesDescriptor{}
				if err = xml.Unmarshal(data, entities); err != nil {
					return nil, err
				}
				err = fmt.Errorf("no entity found with IDPSSODescriptor")
				for _, ed := range entities.EntityDescriptors {
					if len(ed.IDPSSODescriptors) > 0 {
						entity = &ed
						err = nil
					}
				}
				if err != nil {
					return nil, err
				}
			}
			m.ServiceProvider.IDPMetadata = entity
			return m, nil
		case <-globalServiceDoneCh:
			return nil, errors.New("Server is closing")
		}
	}
}
