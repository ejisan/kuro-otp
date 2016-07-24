name := """scalauth-otp"""

organization := "com.ejisan"

version := "1.0.0"

scalaVersion := "2.11.8"

scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked")

crossScalaVersions := Seq("2.10.6", scalaVersion.value)

libraryDependencies += "org.specs2" %% "specs2-core" % "3.8.3" % "test"
