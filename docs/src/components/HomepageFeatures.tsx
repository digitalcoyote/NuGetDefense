import useBaseUrl from '@docusaurus/useBaseUrl';
import React from 'react';
import clsx from 'clsx';
import styles from './HomepageFeatures.module.css';

type FeatureItem = {
  title: string;
  image: string;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Easy to Use',
    image: '/img/wand-magic-sparkles-solid.svg',
    description: (
      <>
        NuGetDefense runs automatically and lets you about vulnerabilities as part of your build. Keeps itself up to date with the latest reported vulnerabilities with the help of a self-updating cache and multiple third Party API's.
      </>
    ),
  },
  {
    title: 'Cross-Platform',
    image: '/img/laptop-code-solid.svg',
    description: (
      <>
        Built to run where you need it. Whether you're auditing an enterprise .Net 4.x ASP.Net project or bleeding edge .Net 6 Web API.
      </>
    ),
  },
  {
    title: 'Configurable',
    image: '/img/user-shield-solid.svg',
    description: (
      <>
        Keeps you safe while respecting your privacy and security decisions. Ignore CVE's, block unapproved Packages, or even restrict packages sent to third party services.
      </>
    ),
  },
];

function Feature({title, image, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <img
          className={styles.featureSvg}
          alt={title}
          src={useBaseUrl(image)}
        />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
