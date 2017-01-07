name := """scalauthx-otp"""

organization := "com.ejisan"

version := "2.0.0"

scalaVersion := "2.12.1"

scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked")

crossScalaVersions := Seq("2.10.6", "2.11.8", scalaVersion.value)

libraryDependencies += "org.specs2" %% "specs2-core" % "3.8.6" % Test

publishTo := Some(Resolver.file("ejisan", file(Path.userHome.absolutePath+"/Development/repo.ejisan"))(Patterns(true, Resolver.mavenStyleBasePattern)))
