from distutils.core import setup
import os

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='python-particle',
    version='0.2',
    packages=['particle'],
    include_package_data=True,
    license='MIT License',  # example license
    description='A Python wrapper around the Particle (particle.io) Cloud API',
    long_description=README,
    install_requires = [
        'python-dateutil==2.4.2',
        'pytz==2015.4',
        'requests==2.7.0',
    ],
    url='https://github.com/DarkSector/python-particle',
    author='Pronoy Chopra',
    author_email='contact@pronoy.in',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        #'Framework :: Requests',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License', # example license
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
